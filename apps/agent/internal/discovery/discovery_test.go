package discovery

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kfake "k8s.io/client-go/kubernetes/fake"
	mfake "k8s.io/client-go/metadata/fake"
)

func ctrl(kind, name string) []metav1.OwnerReference {
	t := true
	return []metav1.OwnerReference{{Kind: kind, Name: name, Controller: &t}}
}

func TestResolveOwner(t *testing.T) {
	lookup := func(kind, name string) []metav1.OwnerReference {
		switch {
		case kind == "ReplicaSet" && name == "web-abc":
			return ctrl("Deployment", "web")
		case kind == "Job" && name == "backup-123":
			return ctrl("CronJob", "backup")
		}
		return nil
	}
	tests := []struct {
		refs []metav1.OwnerReference
		want Owner
	}{
		{nil, Owner{"Pod", "p"}},
		{ctrl("ReplicaSet", "web-abc"), Owner{"Deployment", "web"}},
		{ctrl("ReplicaSet", "orphan"), Owner{"ReplicaSet", "orphan"}},
		{ctrl("Job", "backup-123"), Owner{"CronJob", "backup"}},
		{ctrl("StatefulSet", "db"), Owner{"StatefulSet", "db"}},
		{ctrl("Node", "cp-1"), Owner{"StaticPod", "p"}},
		{[]metav1.OwnerReference{{Kind: "ConfigMap", Name: "x"}}, Owner{"Pod", "p"}},
	}
	for _, tt := range tests {
		if got := ResolveOwner("p", tt.refs, lookup); got != tt.want {
			t.Errorf("%+v: got %+v want %+v", tt.refs, got, tt.want)
		}
	}
}

func TestDiscoverer(t *testing.T) {
	pods := []runtime.Object{
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "web-abc-1", Namespace: "web", OwnerReferences: ctrl("ReplicaSet", "web-abc")},
			Spec: corev1.PodSpec{
				InitContainers: []corev1.Container{{Name: "init", Image: "busybox:1.36"}},
				Containers:     []corev1.Container{{Name: "nginx", Image: "nginx:1.27.1"}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{
				{Name: "nginx", ImageID: "docker.io/library/nginx@sha256:abc"},
			}},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "done", Namespace: "web"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "x"}}},
			Status:     corev1.PodStatus{Phase: corev1.PodSucceeded},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "sys", Namespace: "kube-system"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "y"}}},
		},
	}
	scheme := runtime.NewScheme()
	_ = metav1.AddMetaToScheme(scheme)
	rs := &metav1.PartialObjectMetadata{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "ReplicaSet"},
		ObjectMeta: metav1.ObjectMeta{Name: "web-abc", Namespace: "web", OwnerReferences: ctrl("Deployment", "web")},
	}
	md := mfake.NewSimpleMetadataClient(scheme, rs)

	d, err := New(kfake.NewClientset(pods...), md, Options{ExcludeNamespaces: []string{"kube-system"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := d.Start(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := d.Pods()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d pods: %+v", len(got), got)
	}
	p := got[0]
	if p.Owner != (Owner{"Deployment", "web"}) || len(p.Containers) != 2 || !p.Containers[0].Init || p.Containers[1].ImageID != "docker.io/library/nginx@sha256:abc" {
		t.Errorf("pod: %+v", p)
	}
}
