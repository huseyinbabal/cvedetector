// Package discovery watches pods and reports the images that are running,
// together with the workload that owns each pod. It only reads metadata from
// the API server; no image is pulled or inspected.
package discovery

import (
	"context"
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/metadata/metadatainformer"
	"k8s.io/client-go/tools/cache"
)

// Owner is the top-level workload owning a pod.
type Owner struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// Container is one container (regular, init or ephemeral) of a pod.
type Container struct {
	Name    string
	Image   string // spec image reference
	ImageID string // status imageID, contains the digest once running
	Init    bool
}

// Pod is the subset of a pod the matcher needs.
type Pod struct {
	Namespace  string
	Name       string
	Owner      Owner
	Containers []Container
}

// Options filters namespaces.
type Options struct {
	IncludeNamespaces []string
	ExcludeNamespaces []string
}

var (
	rsGVR  = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}
	jobGVR = schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}
)

// Discoverer keeps informer caches for pods, replicasets and jobs.
type Discoverer struct {
	opts      Options
	factory   informers.SharedInformerFactory
	meta      metadatainformer.SharedInformerFactory
	pods      listersv1.PodLister
	podInf    cache.SharedIndexInformer
	rsLister  cache.GenericLister
	jobLister cache.GenericLister
	changed   chan struct{}
}

// New builds a Discoverer. Call Start before Pods.
func New(cs kubernetes.Interface, md metadata.Interface, opts Options) (*Discoverer, error) {
	d := &Discoverer{opts: opts, changed: make(chan struct{}, 1)}
	d.factory = informers.NewSharedInformerFactory(cs, 0)
	d.meta = metadatainformer.NewSharedInformerFactory(md, 0)

	podInf := d.factory.Core().V1().Pods()
	d.podInf = podInf.Informer()
	if err := d.podInf.SetTransform(stripPod); err != nil {
		return nil, err
	}
	d.pods = podInf.Lister()
	_, err := d.podInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { d.notify() },
		UpdateFunc: func(o, n any) { d.notifyIfImagesChanged(o, n) },
		DeleteFunc: func(any) { d.notify() },
	})
	if err != nil {
		return nil, err
	}
	d.rsLister = d.meta.ForResource(rsGVR).Lister()
	d.jobLister = d.meta.ForResource(jobGVR).Lister()
	return d, nil
}

// Start starts the informers and blocks until their caches are synced.
func (d *Discoverer) Start(ctx context.Context) error {
	d.factory.Start(ctx.Done())
	d.meta.Start(ctx.Done())
	for typ, ok := range d.factory.WaitForCacheSync(ctx.Done()) {
		if !ok {
			return fmt.Errorf("cache sync failed for %v", typ)
		}
	}
	for gvr, ok := range d.meta.WaitForCacheSync(ctx.Done()) {
		if !ok {
			return fmt.Errorf("cache sync failed for %v", gvr)
		}
	}
	return nil
}

// Changed signals (coalesced) that the set of running images may have changed.
func (d *Discoverer) Changed() <-chan struct{} { return d.changed }

func (d *Discoverer) notify() {
	select {
	case d.changed <- struct{}{}:
	default:
	}
}

func (d *Discoverer) notifyIfImagesChanged(o, n any) {
	op, ok1 := o.(*corev1.Pod)
	np, ok2 := n.(*corev1.Pod)
	if !ok1 || !ok2 || op.Status.Phase != np.Status.Phase || !slices.Equal(fingerprint(op), fingerprint(np)) {
		d.notify()
	}
}

func fingerprint(p *corev1.Pod) []string {
	var out []string
	for _, c := range p.Spec.Containers {
		out = append(out, c.Image)
	}
	for _, s := range p.Status.ContainerStatuses {
		out = append(out, s.ImageID)
	}
	return out
}

// Pods returns running (non-terminated) pods after namespace filtering.
func (d *Discoverer) Pods() ([]Pod, error) {
	list, err := d.pods.List(labels.Everything())
	if err != nil {
		return nil, err
	}
	out := make([]Pod, 0, len(list))
	for _, p := range list {
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed || !d.namespaceAllowed(p.Namespace) {
			continue
		}
		out = append(out, Pod{
			Namespace:  p.Namespace,
			Name:       p.Name,
			Owner:      ResolveOwner(p.Name, p.OwnerReferences, d.lookup(p.Namespace)),
			Containers: containers(p),
		})
	}
	return out, nil
}

func (d *Discoverer) namespaceAllowed(ns string) bool {
	if len(d.opts.IncludeNamespaces) > 0 && !slices.Contains(d.opts.IncludeNamespaces, ns) {
		return false
	}
	return !slices.Contains(d.opts.ExcludeNamespaces, ns)
}

// lookup returns the owner references of a ReplicaSet or Job in ns.
func (d *Discoverer) lookup(ns string) func(kind, name string) []metav1.OwnerReference {
	return func(kind, name string) []metav1.OwnerReference {
		var l cache.GenericLister
		switch kind {
		case "ReplicaSet":
			l = d.rsLister
		case "Job":
			l = d.jobLister
		default:
			return nil
		}
		obj, err := l.ByNamespace(ns).Get(name)
		if err != nil {
			return nil
		}
		if m, ok := obj.(*metav1.PartialObjectMetadata); ok {
			return m.OwnerReferences
		}
		return nil
	}
}

// ResolveOwner walks Pod -> ReplicaSet -> Deployment and Pod -> Job -> CronJob.
// Other controllers (StatefulSet, DaemonSet, custom resources) are returned
// as-is; a pod without a controller is its own owner.
func ResolveOwner(podName string, refs []metav1.OwnerReference, lookup func(kind, name string) []metav1.OwnerReference) Owner {
	ref := controllerOf(refs)
	if ref == nil {
		return Owner{Kind: "Pod", Name: podName}
	}
	if ref.Kind == "Node" { // mirror pod of a static pod (control plane components)
		return Owner{Kind: "StaticPod", Name: podName}
	}
	if ref.Kind == "ReplicaSet" || ref.Kind == "Job" {
		if parent := controllerOf(lookup(ref.Kind, ref.Name)); parent != nil {
			return Owner{Kind: parent.Kind, Name: parent.Name}
		}
	}
	return Owner{Kind: ref.Kind, Name: ref.Name}
}

func controllerOf(refs []metav1.OwnerReference) *metav1.OwnerReference {
	for i := range refs {
		if refs[i].Controller != nil && *refs[i].Controller {
			return &refs[i]
		}
	}
	return nil
}

func containers(p *corev1.Pod) []Container {
	ids := map[string]string{}
	for _, list := range [][]corev1.ContainerStatus{p.Status.ContainerStatuses, p.Status.InitContainerStatuses, p.Status.EphemeralContainerStatuses} {
		for _, s := range list {
			ids[s.Name] = s.ImageID
		}
	}
	var out []Container
	for _, c := range p.Spec.InitContainers {
		out = append(out, Container{Name: c.Name, Image: c.Image, ImageID: ids[c.Name], Init: true})
	}
	for _, c := range p.Spec.Containers {
		out = append(out, Container{Name: c.Name, Image: c.Image, ImageID: ids[c.Name]})
	}
	for _, c := range p.Spec.EphemeralContainers {
		out = append(out, Container{Name: c.Name, Image: c.Image, ImageID: ids[c.Name]})
	}
	return out
}

// stripPod keeps only the fields the agent reads, to keep the informer cache
// small on large clusters.
func stripPod(obj any) (any, error) {
	p, ok := obj.(*corev1.Pod)
	if !ok {
		return obj, nil
	}
	s := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: p.Name, Namespace: p.Namespace, UID: p.UID,
			ResourceVersion: p.ResourceVersion, OwnerReferences: p.OwnerReferences,
		},
		Status: corev1.PodStatus{Phase: p.Status.Phase},
	}
	for _, c := range p.Spec.InitContainers {
		s.Spec.InitContainers = append(s.Spec.InitContainers, corev1.Container{Name: c.Name, Image: c.Image})
	}
	for _, c := range p.Spec.Containers {
		s.Spec.Containers = append(s.Spec.Containers, corev1.Container{Name: c.Name, Image: c.Image})
	}
	for _, c := range p.Spec.EphemeralContainers {
		ec := corev1.EphemeralContainer{}
		ec.Name, ec.Image = c.Name, c.Image
		s.Spec.EphemeralContainers = append(s.Spec.EphemeralContainers, ec)
	}
	strip := func(in []corev1.ContainerStatus) []corev1.ContainerStatus {
		var out []corev1.ContainerStatus
		for _, cs := range in {
			out = append(out, corev1.ContainerStatus{Name: cs.Name, Image: cs.Image, ImageID: cs.ImageID})
		}
		return out
	}
	s.Status.ContainerStatuses = strip(p.Status.ContainerStatuses)
	s.Status.InitContainerStatuses = strip(p.Status.InitContainerStatuses)
	s.Status.EphemeralContainerStatuses = strip(p.Status.EphemeralContainerStatuses)
	return s, nil
}
