# SPEC: cvedetector

> Durum: v0.7, Helm chart huseyinbabal/charts reposuna, ürün kataloğu `data` branch'ine taşındı · Tarih: 2026-11-19

## 1. Amaç

İsim: **cvedetector** (tek kelime). 2026-11-19 itibarıyla GitHub organizasyonu, Docker Hub, npm, PyPI ve Artifact Hub'da bu isim boş. Tireli `cve-detector` ise tek bir CVE için yazılmış birçok PoC tespit script'inde geçiyor; karışmaması için her yerde tek kelime yazılır.

Kubernetes cluster'larında **o anda çalışan** container imajlarını bulup, GitHub'da tutulan bir CVE feed'i ile eşleştirerek hangi workload'ın hangi CVE'lerden etkilendiğini göstermek. Ek olarak bu bilgiyi zaman içinde izlemek: bir CVE ne zaman göründü, ne zaman kapandı.

**Temel prensip: hiçbir yerde tarama yok.** Ne cluster'da ne GitHub Actions'ta imaj çekilir, layer açılır veya SBOM üretilir.

- Feed tarafı: imaj repository'leri bir "ürün"e eşlenir (`nginx` → NGINX). Ürünün CVE'leri ve etkilenen sürüm aralıkları NVD ve OSV'den alınır.
- Eşleştirme: imajın tag'inden sürüm okunur (`nginx:1.27.1` → `1.27.1`) ve aralıklarla karşılaştırılır.

### Bu yaklaşımın sınırı (bilinçli trade-off)
Sadece imajın ana yazılımının CVE'leri bulunur. İmajın içindeki işletim sistemi paketleri görülmez. Debian/Ubuntu tabanlı imajlarda sürüm numarası değişmeden yapılan yama backport'ları yanlış pozitif üretebilir.

### Kapsam dışı (şimdilik)
- Her türlü imaj/SBOM taraması, OS paketi CVE'leri.
- Private/kendi uygulama imajları (ürün eşlemesi olmadığı için "Coverage gaps" sayfasında listelenir).
- Admission control, otomatik düzeltme.
- UI'da kimlik doğrulama/SSO (bkz. §10).
- CVE ignore / VEX.

## 2. Mimari

```
 GitHub ───────────────────────────────────────────────────────────────
  data:catalog/*.yaml ─► Actions feed.yml (günlük) ─► tools/feedgen
  (PR + discover.yml)
                         NVD + OSV (+ KEV, EPSS) ─► v1/index.json + v1/products/<id>.json
                                                    sadece değişiklikte commit → `data` branch'i
                                                              │ HTTPS (ETag)
 Merkez (bir cluster) ────────────────────────────────────────┼─────────
                                                              ▼
   ui (nginx)  ── GET /api/* ──►  api (Deployment, N replika) ──► PostgreSQL
   statik React                    ├─ feed sync (advisory lock: tek replika)  (bundled StatefulSet
                                   ├─ POST /api/v1/ingest (Bearer token)       ya da external)
                                   ├─ eşleştirme + bulgu uzlaştırma
                                   └─ read API, /metrics
                                         ▲
 Her cluster ────────────────────────────┼──────────────────────────────
   agent (Deployment, 1 pod, read-only RBAC)
     pod informer → envanter raporu (imajlar + workload'lar), gzip JSON
```

**Sorumluluklar:**
- **Agent** sadece envanter toplar ve API'ye gönderir. Feed'e, internete ve veritabanına erişmez.
- **API** feed'i PostgreSQL'e aynalar, envanteri eşleştirir, bulgu geçmişini tutar ve okuma API'sini sunar.
- **UI** statik bir uygulamadır; `/api` yolunda sadece GET isteklerini API'ye geçirir.

**Neden eşleştirme agent'ta değil de API'de:**
1. Yeni bir CVE feed'e girdiğinde, cluster'da hiçbir şey değişmese bile bulgular güncellenir; API feed değişince tüm cluster'ları yeniden eşleştirir.
2. Agent'ın internete çıkması gerekmez.
3. Birden fazla cluster tek bir API'ye bağlanabilir.

## 3. Monorepo yapısı

```
cvedetector/
├── apps/
│   ├── agent/          # Go. cmd/agent, internal/{discovery,report}. Dockerfile (distroless)
│   ├── api/            # Go. cmd/api, internal/{db,store,matcher,feedsync,httpapi,metrics}. Dockerfile (distroless)
│   └── ui/             # React + TS + Vite + Tailwind + shadcn/ui. Dockerfile (nginx-unprivileged), nginx.conf.template
├── tools/feedgen/      # feed üretici (NVD, OSV, CISA KEV, EPSS); discover/ = otomatik keşif
├── pkg/
│   ├── feed/           # feed şeması + aralık eşleştirme
│   ├── inventory/      # agent → API rapor sözleşmesi
│   ├── version/        # gevşek semver karşılaştırma
│   └── imageref/       # imaj referansı normalizasyonu
└── .github/workflows/{ci,feed,release}.yml
```

- Tek Go modülü.
- Üç ayrı imaj: `cvedetector-agent`, `cvedetector-api`, `cvedetector-ui`.
- Ürün kataloğu ve feed verisi `main`'de değil, ayrı bir `data` branch'inde (§4.3). `main`'de sadece kod var.

## 4. Feed

### 4.1 Ürün kataloğu: `catalog/<id>.yaml` (`data` branch'i)
CVE veritabanları imaja göre değil **ürüne** göre tutulur: NVD'de "`cpe:2.3:a:php:php` sürüm 8.3.0 ile 8.3.14 arası etkilenir" gibi kayıtlar vardır. "`docker.io/library/php` imajı = `php:php` ürünü" eşlemesini hiçbir veritabanı tutmaz. Bütün CVE'leri çekmek tek başına bir işe yaramaz; asıl iş bu eşlemeyi kurmak. Katalog bu eşlemedir ve iki yoldan büyür:

1. **Pull request ile katkı** (`data` branch'ine).
   - Katalog, ondan üretilen feed ile birlikte `data` branch'inde durur; `main` kalabalıklaşmaz. Araçlar (`feedgen`) `main`'de olduğu için yerel kontrol `-config <data checkout>/catalog` ile yapılır.
   - Her ürün ayrı bir dosyada olduğu için aynı anda yapılan katkılar çakışmaz.
   - Dosyanın içeriği: `id` (dosya adıyla aynı olmalı), `name`, `images` (registry dahil tam repository adları), `nvd.cpes` ve/veya `osv` paketleri, gerekiyorsa `versionPattern` ve `minSegments`, ve **zorunlu `testTags`**: gerçek tag'ler ve onlardan okunması gereken sürüm.
   - `feedgen -validate` şunları kontrol eder: şema, dosya adı ile id'nin uyuşması, registry'siz ya da tag'li imaj adı, aynı imajın iki ürüne eşlenmesi, test tag'lerinin beklenen sürümü vermesi, CPE formatı.
   - `data` branch'indeki `.github/workflows/catalog.yml` PR'da `main`'den araçları alıp değişen ürünler için `feedgen -probe` çalıştırır: her kaynak kaç CVE döndürüyor, test tag'lerinin sürümleri kaç CVE'den etkileniyor. Rapor job özetine yazılır. Hiç kayıt döndürmeyen bir kaynak (genelde yanlış CPE ya da paket adı) kontrolü başarısız yapar. Bu workflow `data` branch'inde olmak zorunda: GitHub PR workflow'larını hedef branch'ten okur. Merge sonrası aynı workflow `main`'deki `feed.yml`'ı tetikler.
   - UI'daki Coverage gaps sayfasında, cluster'da çalışan tag'lerle ve bu tag'lerden varsayılan kuralla okunan sürümlerle önceden doldurulmuş bir dosyayla GitHub'ın yeni dosya sayfası `data` branch'inde açılır.
   - **Toplu ekleme:** satırlar checkbox ile (tümünü seç dahil) seçilir, Actions → Add to feed. GitHub tek seferde birden fazla dosyayı önceden dolduramadığı için dosyalar zip olarak indirilir ve GitHub'ın `catalog/` yükleme sayfasına bırakılır ("Create a new branch and start a pull request"); alternatif olarak dosyaları yazan bir shell script kopyalanır ya da hepsi için tek bir issue açılır.
   - Id'ler seçim içinde ve feed'deki ürünlerle (`GET /api/v1/products`) çakışmayacak şekilde üretilir; yükleme sayfası aynı adlı dosyanın üzerine yazacağı için bu gerekli. Çakışma varsa (ör. `ghcr.io/fluent/fluent-bit` ↔ `fluent-bit`) id namespace ile önek alır ve UI imajı yeni ürün yerine mevcut dosyanın `images` listesine eklemeyi önerir. Yazma yetkisi olmayan biri için GitHub otomatik olarak fork açar ve PR'a yönlendirir.
   - `CONTRIBUTING.md`, PR şablonu ve "Track an image" issue formu da bu akışı destekler.
2. **Otomatik keşif** (`tools/feedgen/discover`, `discover.yml`, her pazartesi):
   - **Adaylar** gerçekten çalıştırılan imajlardan toplanır: Artifact Hub'ın en çok yıldız alan 300 Helm chart'ının kullandığı imajlar (`containers_images`), Docker Official Images (`docker-library/official-images`) ve Bitnami imajları (`bitnami/containers`). Kaç chart'ta geçtiklerine göre sıralanır.
   - **Tag'ler** registry'den okunur (sadece metadata; Docker Hub API'si ya da OCI `/v2/tags/list` anonim token ile). Tag'lerin çoğu sürüm taşımıyorsa (MinIO'nun `RELEASE.…` tag'leri gibi) imaj elenir. Test tag'leri gerçek tag'lerden üretilir.
   - **NVD CPE sözlüğünde** imaj adıyla ürün aranır. Sadece adı birebir eşleşen ve CVE kaydı olan ürünler kabul edilir. Sürümü değiştirmeyen ekler (`-server`, `-community`, `-oss`, `-ce`, `-ee`) dışında isim kırpılmaz; `-operator` ya da `-k8s` gibi ekler asla kırpılmaz. Örnek: `vault-k8s` Vault değildir.
   - **Sürüm tutarlılığı kontrolü:** imajın en yeni sürümünün major numarası, ürünün CVE aralıklarında geçmiyorsa eşleşme reddedilir.
   - **Birden fazla üretici** varsa üretici adı ürün adına ya da imajın namespace'ine eşitse o seçilir; değilse imaj raporda "elle incelenmeli" olarak listelenir.
   - Mevcut bir ürünün CPE'sine düşen imaj, o ürünün `images` listesine eklenir (örneğin `docker.gitea.com/gitea` → `gitea`).
   - Sonuçlar **asla doğrudan yazılmaz**; rapor gövdesiyle birlikte `data` branch'ine bir PR açılır. NVD yanıtları cache'lenir, böylece sonraki haftalarda sadece yeni adaylar sorgulanır.

### 4.2 Üretim
`tools/feedgen` NVD'den (CPE ile) ve OSV'den CVE'leri ve etkilenen sürüm aralıklarını çeker ve birleştirir, CISA KEV ile zenginleştirir, EPSS skorlarını ayrı bir dosyaya yazar.

Bilinen tuzaklar:
- CoreDNS NVD'de bulunmuyor, OSV Go modülü kullanılıyor.
- Prometheus ve Grafana'nın Go modül sürümleri imaj tag'leriyle uyuşmuyor, NVD CPE kullanılıyor.
- Probe'da external-dns, kube-state-metrics, metrics-server, node-exporter, thanos, rook ve longhorn için OSV hiç kayıt döndürmedi; katalogda yoklar.

### 4.3 Saklama: `data` branch'i
Katalog ve feed, kodla aynı repoda ama ayrı bir **`data` branch'inde** (geçmişiyle birlikte) tutulur. `main` bot commit'leriyle ve katalog dosyalarıyla kalabalıklaşmaz, klonlaması hafif kalır.

```
catalog/<id>.yaml         ürün kataloğu (girdi; PR ile değişir)
.github/workflows/catalog.yml   katalog PR kontrolü ve merge sonrası feed tetikleme
v1/index.json             ürünler, imaj eşlemesi, tüm dosyaların sha256'sı
v1/products/<id>.json     ürünün güncel CVE'leri ve affected aralıkları
v1/epss.json              EPSS skorları (her gün değişir; ayrı tutulur)
changes/YYYY/MM/YYYY-MM-DD.json   o gün eklenen, güncellenen ve kaldırılan CVE'ler
README.md
```

**Neden zamana göre bölünmüş (aylık ya da günlük) CVE dosyaları değil:**
- API her zaman güncel tam resme ihtiyaç duyuyor.
- NVD eski CVE'leri sürekli güncelliyor: CVSS değişiyor, etkilenen aralıklar düzeltiliyor, KEV'e ekleniyor. Yayın ayına göre bölünmüş dosyalarda eski aylar da her gün değişirdi ve API her seferinde tüm ayları okumak zorunda kalırdı.

Bunun yerine `v1/` altında **ürün başına güncel durum** tutuluyor; tarihçe için iki şey var:
- **Git geçmişi:** örneğin `git log -p -- v1/products/nginx.json` NGINX'in CVE'lerinin zaman içindeki değişimini gösterir.
- **Günlük changelog** (`changes/`): insanlar ve ileride bildirimler için küçük, okunabilir dosyalar. Aynı gün birden fazla çalıştırma olursa aynı dosyada birleştirilir.

**Sadece değişiklik varsa commit:**
- Çıktı deterministik: shard'larda zaman damgası yok, CVE'ler ID'ye göre sıralı, NVD'nin sık güncellediği `modified` alanı çıkarılmış, EPSS ayrı dosyada.
- feedgen önceki çıktıyı okuyup karşılaştırır; değişiklik yoksa hiçbir dosyaya dokunmaz.
- `index.json`'daki `generatedAt` son içerik değişikliğinin zamanıdır.
- Commit mesajı yeni CVE'leri listeler: `feed 2026-11-20: 3 new, 5 updated, 0 removed`.
- Pratikte EPSS her gün değiştiği için hemen her gün en az bir commit olur.

**İlk gerçek veriyle ölçülen:** 3 ürünle iki ardışık çalıştırmada ilki "initial import" commit'i üretti, ikincisi "unchanged" dedi ve hiçbir dosyaya dokunmadı.

### 4.4 Workflow (`feed.yml`)
- Her gün 03:17 UTC'de çalışır; ayrıca elle, `main`'de `tools/feedgen` değişince ve `data`'da katalog değişikliği merge edilince (`catalog.yml` üzerinden) tetiklenir.
- Adımlar: testler → `data` branch'i bir worktree'ye alınır → `feedgen -config data/catalog -out data -changes data/changes -commit-message …` → değişiklik varsa `github-actions[bot]` adına commit ve push. Özet, job'ın Summary sayfasına yazılır.
- `NVD_API_KEY` secret'ı opsiyonel. Anahtarsız bir çalışma yaklaşık 5 dakika, anahtarla yaklaşık 1 dakika sürer. Private repoda Actions dakikaları aylık kotadan düşer.
- Cosign imzası kaldırıldı: keyless imza herkese açık transparency log'a (Rekor) private reponun adını yazardı. Repo public olunca geri eklenebilir.

### 4.5 Tüketim
- API feed'i `https://raw.githubusercontent.com/huseyinbabal/cvedetector/data/` adresinden okur.
- Repo private olduğu için `FEED_TOKEN` gerekir: `contents: read` yetkili, fine-grained bir GitHub token'ı. Helm'de `api.feed.existingTokenSecret` ile verilir.
- Go HTTP istemcisi, bir yönlendirme başka bir host'a giderse `Authorization` başlığını göndermez; token sızmaz.
- Index'te `epss.json`'un checksum'ı da var; API, EPSS dosyası ya da shard'lar değişince skorları yeniden uygular.

## 5. Agent

- **Keşif:**
  - Pod informer, bellek tasarrufu için sadece isim, owner, imaj ve imageID alanlarını tutar.
  - ReplicaSet ve Job için sadece metadata informer kullanılır.
  - Owner çözümü: Pod → ReplicaSet → Deployment, Pod → Job → CronJob, Node sahipli pod → `StaticPod`.
  - `Succeeded`/`Failed` pod'lar hariç tutulur; init ve ephemeral container'lar dahildir.
- **Rapor (`pkg/inventory.Report`):**
  - Tekil imajlar: ref, repository, tag, çalışan digest'ler, pod sayısı.
  - Workload'lar: namespace, kind, name, pod sayısı, imaj ref'leri.
  - Gzip'li JSON olarak `POST /api/v1/ingest` adresine gönderilir.
- **Ne zaman gönderilir:**
  - Pod değişince, debounce süresinden sonra (varsayılan 5 sn).
  - Envanter değişmediyse gönderilmez. Bunu sıra ve zamandan bağımsız bir `Fingerprint` ile anlar.
  - Değişiklik olmasa da en geç `RESYNC_INTERVAL`'da (varsayılan 10 dk) heartbeat olarak gönderilir.
- **Hata durumu:** gönderemezse 2 sn'den 2 dk'ya kadar artan aralıklarla tekrar dener. Sadece en son envanteri tutar, kuyruk biriktirmez.
- **Konfigürasyon:**
  - Zorunlu: `CLUSTER_NAME` (DNS-label formatında), `API_URL`, `INGEST_TOKEN` (ya da `INGEST_TOKEN_FILE`).
  - Opsiyonel: `RESYNC_INTERVAL`, `DEBOUNCE`, `NAMESPACES_INCLUDE` / `NAMESPACES_EXCLUDE`, `LISTEN_ADDR`.
- **RBAC:** `pods`, `apps/replicasets` ve `batch/jobs` üzerinde sadece `get/list/watch`.
- **Metrikler:**
  - `cvedetector_agent_reports_total{result=sent|skipped|error}`
  - `cvedetector_agent_last_report_success_timestamp_seconds`
  - `cvedetector_agent_pods`
  - `cvedetector_agent_images`

## 6. API

### 6.1 Çalışma
- **Veritabanı zorunlu.** Bağlantı `DATABASE_URL` ile ya da standart `PG*` ortam değişkenleriyle (`PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`, `PGSSLMODE`) verilir. Hiçbiri yoksa API açılmaz. Veritabanı henüz hazır değilse 3 dakika boyunca tekrar dener.
- **Migration'lar** gömülü SQL dosyalarıdır (`internal/db/migrations`) ve açılışta uygulanır. Birden fazla replika aynı anda açılırsa diye advisory lock alınır; kayıtlar `schema_migrations` tablosunda tutulur.
- **Feed sync:**
  - Her `FEED_REFRESH_INTERVAL`'da (varsayılan 1 saat) çalışır. Advisory lock sayesinde aynı anda sadece bir replika çalıştırır.
  - Önce index çekilir. ETag kullanılır; sunucu ETag vermiyorsa içeriğin hash'i kullanılır.
  - Sadece sha256'sı değişen shard'lar indirilir ve doğrulanır.
  - Ürün metadata'sı her zaman güncellenir, çünkü imaj eşlemesi shard değişmeden de değişebilir.
  - Index'te artık olmayan ürünler silinir.
  - Bunların hepsi tek transaction'da yapılır ve `feed_state.revision` artırılır. Ardından tüm cluster'lar yeniden eşleştirilir.
  - Hata olursa önceki feed olduğu gibi kalır ve hata `feed_state.last_error` alanına yazılır.
- **Catalog önbelleği:** her replika eşleştirme katalogunu bellekte tutar ve `feed_state.revision` değişince veritabanından yeniden yükler.

### 6.2 Veri modeli (PostgreSQL)

| Tablo | İçerik |
|---|---|
| `clusters` | name, agent_version, first_seen, last_report, fingerprint |
| `images` | cluster'ın **güncel** imajları: ref, repository, tag, digests, pods, product, version, status |
| `workloads`, `workload_images` | güncel workload'lar ve kullandıkları imajlar |
| `feed_state` | tek satır: url, generated_at, etag, last_attempt/success/error, revision |
| `products`, `vulns` | feed'in aynası; `vulns.affected` jsonb olarak tutulur |
| `findings` | **geçmiş:** (cluster, ref, product, vuln_id, fixed_in, first_seen, last_seen, resolved_at) |

**Bulgu yaşam döngüsü.** Envanter geldiğinde ya da feed değiştiğinde, istenen (imaj, CVE) çiftleri hesaplanır ve mevcut açık bulgularla uzlaştırılır:
- Yeni çift → yeni satır açılır (`first_seen = now`).
- Artık görünmeyen çift → `resolved_at = now`. Sebep imajın yükseltilmesi ya da kaldırılması, ya da feed'in o CVE'yi artık listelememesi olabilir.
- Devam eden çift → `last_seen` güncellenir; düzeltme sürümü değiştiyse `fixed_in` de güncellenir.

Açık bulgu tekilliği kısmi bir unique index ile sağlanır (`WHERE resolved_at IS NULL`). Aynı cluster'a ait ingest ve yeniden eşleştirme `pg_advisory_xact_lock` ile sıraya konur.

Envanter fingerprint'i değişmediyse sadece `last_report` güncellenir; tablolara dokunulmaz.

**Saklama:** kapanmış bulgular `RETENTION` süresinden (varsayılan 365 gün) sonra günlük bir job ile silinir.

### 6.3 Endpoint'ler

| Endpoint | Açıklama |
|---|---|
| `POST /api/v1/ingest` | Agent raporu. `Authorization: Bearer <token>`, gzip destekli, en fazla 64 MB, şema doğrulamalı. Yanıt `202 {images, opened, resolved, open, changed}` |
| `DELETE /api/v1/clusters/{name}` | Cluster'ı ve tüm geçmişini siler (token gerekir) |
| `GET /api/v1/clusters` | Cluster'lar: son rapor zamanı, agent sürümü, imaj/workload sayısı, severity dağılımı |
| `GET /api/v1/summary?cluster=` | Severity sayıları (tekil CVE), KEV, fixable, imaj durumları, en riskli 10 workload, ürün dağılımı |
| `GET /api/v1/history?cluster=&days=30` | Gün sonu açık CVE sayıları (severity'ye göre), açılan ve kapanan bulgu sayısı, ortalama düzeltme süresi, takibin başladığı tarih |
| `GET /api/v1/images` · `/workloads` · `/cves` | Sayfalı liste: `{items, total}` |
| `GET /api/v1/image?cluster=&ref=` | İmaj + açık CVE'ler (`fixedIn`, `firstSeen`) + kapanmış CVE'ler + kullanan workload'lar |
| `GET /api/v1/workloads/{cluster}/{ns}/{kind}/{name}` | Workload + imajları |
| `GET /api/v1/cves/{id}?cluster=` | CVE + etkilenen imajlar (`firstSeen`) + kapanmış olanlar + workload'lar |
| `GET /api/v1/feed`, `/namespaces` | Feed durumu, namespace listesi |
| `GET /api/v1/products` | Feed'deki ürünler (id, ad, imajlar, CVE sayısı) |
| `GET /healthz`, `/readyz` (DB ping), `/metrics` | |

**Liste parametreleri:**
- Filtre: `cluster`, `namespace`, `q`, `minSeverity`, `status`, `product`, `kev`, `fixable`.
- Sıralama: `sort` ve `order` (`asc` | `desc`). Sıralama anahtarları beyaz listeyle sınırlı.
- Sayfalama: `limit` (en fazla 500) ve `offset`. Toplam sayı `count(*) OVER()` ile aynı sorguda hesaplanır.

CVE listesinin varsayılan sırası önceliklendirmeye göre: önce KEV, sonra severity, CVSS ve etkilenen workload sayısı.

**ETag:** tüm GET yanıtlarında içerik hash'inden üretilen bir ETag var; `If-None-Match` gelirse `304` dönülür. UI 30 saniyede bir sorgu attığı için değişmeyen veride gövde gönderilmez.

### 6.4 Konfigürasyon

| Env | Varsayılan |
|---|---|
| `DATABASE_URL` / `PG*` | zorunlu |
| `INGEST_TOKEN`, `INGEST_TOKENS` (virgülle ayrılmış ek token'lar) | en az biri zorunlu |
| `FEED_URL`, `FEED_REFRESH_INTERVAL` | `https://raw.githubusercontent.com/huseyinbabal/cvedetector/data/`, `1h` |
| `FEED_TOKEN` | boş (private repo için gerekli) |
| `RETENTION` | `8760h` |
| `WORKLOAD_METRICS` | `false` |
| `LISTEN_ADDR`, `LOG_LEVEL`, `LOG_FORMAT` | `:8080`, `info`, `json` |

### 6.5 Metrikler
Metrikler veritabanından okunur ve 30 saniye önbelleklenir. Her replika aynı değerleri raporladığı için toplarken `sum()` değil `max()` kullanılmalı.
- `cvedetector_cluster_vulnerabilities{cluster,severity}`, `cvedetector_cluster_kev_vulnerabilities{cluster}`: cluster bazında tekil sayı
- `cvedetector_vulnerabilities{cluster,namespace,severity}`
- `cvedetector_kev_vulnerabilities{cluster,namespace}`
- `cvedetector_images{cluster,status}`
- `cvedetector_cluster_last_report_timestamp_seconds{cluster}`: alarm için, agent sustu mu
- `cvedetector_feed_age_seconds`
- `cvedetector_ingest_total{result}`, `cvedetector_feed_sync_errors_total`
- Opsiyonel: `cvedetector_workload_max_severity{cluster,namespace,kind,name,severity}` (`WORKLOAD_METRICS=true`)

## 7. UI

### 7.1 Teknoloji
React 19, TypeScript, Vite, Tailwind CSS v4, shadcn/ui (Radix tabanlı, kaynak kodu `src/components/ui/` altında), Lucide ikonları, TanStack Table v8, cmdk ve sonner. Router olarak hash tabanlı küçük bir router kullanılır.

Build çıktısı `apps/ui/dist` klasörüne yazılır ve `nginxinc/nginx-unprivileged` (uid 101, port 8080) ile sunulur:
- `/api/*` isteklerini `API_URL` adresine proxy'ler; sadece GET ve HEAD.
- `/assets/*` 1 yıl önbelleklenir; `index.html` önbelleğe alınmaz.
- CSP, `nosniff` ve `frame-ancestors 'none'` başlıkları eklenir.

### 7.2 Durum ve veri
- **Cluster seçimi** URL'de `?cluster=` olarak tutulur ve bütün sayfaları bu cluster'a göre filtreler. Seçici üst barda durur ve sadece birden fazla cluster varsa görünür. Seçim yokken listelerde bir Cluster kolonu çıkar.
- **Detay sayfaları** kendi cluster'larını `in=` parametresi ya da URL yolu ile taşır. Böylece bir detaya gitmek global seçimi değiştirmez.
- **Listeler** sunucu tarafında sayfalanır ve sıralanır. `page`, `size`, `sort` ve `order` URL'de tutulur, linkler paylaşılabilir. Filtre değişince sayfa 1'e döner.
- **CSV export** sadece görünen sayfayı değil, filtreye uyan tüm kayıtları API'den sayfa sayfa çekerek oluşturur.
- **`useApi`:** 30 saniyede bir, sadece sekme görünürken yeniler; ETag önbelleği vardır. İptal edilen bir istek yükleme durumunu değiştirmez. Bu, sayfa numarasının kendiliğinden sıfırlanması hatasının düzeltmesidir.

### 7.3 Sayfalar
- **Overview:**
  - severity kutucukları,
  - **son 30 gün trendi**,
  - en riskli workload'lar, imaj kapsaması, ürün dağılımı, feed durumu,
  - hiç cluster rapor vermemişse kurulum yönergesi.
- **Images**, **Workloads**, **Vulnerabilities** listeleri ve detay sayfaları. Detaylarda "Since" ve "Open for" sütunları, ayrıca "Resolved" geçmişi var.
- **CVE yan paneli** (`?cve=`), **⌘K komut paleti** (her listeden risk sırasına göre ilk 300 kayıt), **Coverage gaps**.
- **Clusters:** son rapor zamanı (30 dakikadan eskiyse uyarı), agent sürümü, sayılar ve cluster silme yönergesi.

### 7.4 Trend grafiği
Severity renkleri (kırmızı, turuncu, sarı) renk körlüğünde birbirinden ayırt edilemiyor. Doğrulayıcının sonucu: deutan ΔE 0.6; normal görüşte bile kırmızıyla turuncu arasında ΔE 6.1.

Bu yüzden 4 çizgi tek grafikte değil, **severity başına ayrı küçük grafiklerde** gösteriliyor:
- Her grafiğin kendi y ekseni var; kimliği başlık belirliyor, renk sadece vurgu.
- Crosshair dört grafikte ortak; klavyeyle ←/→ tuşlarıyla gezilebiliyor.
- "Show as table" ile tablo görünümü var.
- Takip başlamadan önceki günler çizilmiyor, çünkü sıfır değerler "açık CVE yoktu" şeklinde yanlış okunur.

## 8. Helm chart

Chart bu repoda değil, **`huseyinbabal/charts`** reposunda (`stable/cvedetector`). Bu repo sadece imajları üretir. Chart'ın `appVersion`'ı imaj tag'idir.

Tek chart, bileşenler ayrı ayrı açılıp kapatılabiliyor:

| Mod | Ayarlar |
|---|---|
| Hepsi bir arada (varsayılan) | agent + api + ui + bundled PostgreSQL |
| External DB | `postgresql.enabled=false`, `externalDatabase.host`, `externalDatabase.existingSecret` (ya da `password`), `sslmode` |
| Sadece agent (uzak cluster) | `api.enabled=false`, `ui.enabled=false`, `postgresql.enabled=false`, `agent.clusterName`, `agent.apiUrl`, `agent.existingTokenSecret` |

- **Doğrulama:** çelişkili ya da eksik ayarlarda `helm install` anlaşılır bir mesajla durur:
  - hem bundled hem external DB,
  - hiç DB yok,
  - external DB'nin şifresi yok,
  - sadece agent modunda URL ya da token yok,
  - API olmadan UI,
  - geçersiz cluster adı.
- **Bundled PostgreSQL:**
  - Resmi `postgres:18.6-alpine` imajıyla tek instance bir StatefulSet.
  - uid 70, read-only root dosya sistemi, `PGDATA` alt dizinde.
  - Varsayılan 8 Gi PVC; NFS değil blok depolama önerilir.
  - Bitnami chart'ı, lisans ve imaj dağıtımı değişikliği yüzünden kullanılmıyor.
  - HA gerekiyorsa managed bir veritabanı ya da CloudNativePG gibi bir operator'ı external olarak bağlamak gerekir.
- **Yayın:** `v*` tag'inde bu repodaki `release.yml` imajları GHCR'a basar ve imzalar. Chart `huseyinbabal/charts`'ta elle güncellenir (`version` ve `appVersion` yeni tag'e çekilir). Oradaki chart-releaser `main`'e merge'de `https://huseyinbabal.github.io/charts` adresine yayınlar; repo Artifact Hub'a bağlı. Chart, imajlar GHCR'da yokken yayınlanmamalı. Kurulum: `helm repo add huseyinbabal https://huseyinbabal.github.io/charts`.
- **Secret'lar:**
  - Ingest token ve PostgreSQL şifresi ilk kurulumda üretilir. `lookup` ile upgrade'lerde korunur ve `helm.sh/resource-policy: keep` ile uninstall'da silinmez; şifre kaybolursa API veri volume'una erişemez.
  - Ek token'lar `api.extraTokensSecret` ile verilir.
- **Ingress:** `/api` doğrudan API'ye gider (uzak agent'lar ingest yapabilsin diye), `/` UI'a gider.
- **İzleme:**
  - `metrics.enabled` Prometheus'un API ve agent'tan metrik toplamasını açar. `metrics.serviceMonitor.enabled` ile ServiceMonitor oluşturulur, yoksa pod'lara `prometheus.io/scrape` annotation'ları eklenir.
  - `metrics.prometheusRule.enabled` hazır alarmları kurar:
    - agent rapor göndermiyor (30 dk),
    - feed eskidi (48 sa),
    - feed senkronizasyonu başarısız,
    - KEV listesinde bir CVE çalışıyor,
    - kritik bir CVE çalışıyor.
    
    Eşikler, severity'ler ve ek kurallar values'tan ayarlanır. Kurallar `promtool check rules` ile doğrulandı.
  - `dashboard.enabled` chart içindeki `dashboards/cvedetector.json` dosyasını Grafana sidecar'ının yüklediği bir ConfigMap olarak kurar (`grafana_dashboard: "1"` etiketi; namespace ve klasör ayarlanabilir). `metrics.enabled` olmadan açılamaz.
  - **Dashboard içeriği:** severity kutucukları, KEV sayısı, feed yaşı; severity başına ayrı trend grafikleri (Grafana repeat, §7.4'teki renk körlüğü gerekçesiyle); cluster/namespace tablosu; imaj kapsaması; cluster'ların son rapor zamanı; rapor akışı; feed hataları; agent'ın gördüğü pod ve imaj sayısı; opsiyonel workload tablosu.
  - Dashboard yerelde Grafana 13.3 + Prometheus ile gerçek metriklere karşı test edildi.
  - Dashboard'un doğru toplam gösterebilmesi için API'ye cluster bazında tekil sayan `cvedetector_cluster_vulnerabilities{cluster,severity}` ve `cvedetector_cluster_kev_vulnerabilities{cluster}` metrikleri eklendi. Namespace bazlı metrik toplanınca birden fazla namespace'teki aynı CVE'yi iki kez sayıyordu.
- **Güvenlik:** tüm container'lar non-root çalışır, root dosya sistemi read-only, `drop: ALL`, seccomp `RuntimeDefault`. API ve UI'da service account token mount edilmez.

## 9. Ölçeklenme

| Boyut | Yaklaşım |
|---|---|
| Büyük tek cluster | Agent bellek dostu (transform ve metadata informer). Liste API'si sayfalı, yanıtlar ETag'li. İngest COPY ile toplu yazar. Workload metriği varsayılan olarak kapalı |
| Çok cluster | Her cluster'da sadece agent, merkezde tek API + PostgreSQL. Cluster başına advisory lock. Cluster seçici ve Clusters sayfası |
| API replikaları | Stateless. Migration ve feed sync advisory lock ile tekilleştirilir; katalog revision'a göre yeniden yüklenir |
| Geçmiş büyümesi | Sadece değişiklikler saklanır (snapshot değil) ve saklama süresiyle budanır. Trend sorgusu `generate_series` ile hesaplanır; çok büyük kurulumlarda günlük özet tablosuna geçilebilir (§10) |
| Feed dağıtımı | Statik dosyalar ve CDN. Sadece API çeker; agent'lar çekmez |

## 10. Açık konular / sonraki adımlar
1. **UI kimlik doğrulaması.** Read API şu an kimlik doğrulamasız; erişim ingress (oauth2-proxy gibi) ya da port-forward ile kısıtlanmalı. Seçenekler: OIDC proxy dokümantasyonu ya da API'de OIDC.
2. **Cluster başına token.** Şu an herhangi geçerli bir token, herhangi bir cluster adıyla rapor gönderebiliyor. Token'ı cluster adına bağlamak gerekli.
3. **Feed imza doğrulaması.** API şu an sadece sha256 kontrol ediyor; cosign doğrulaması eklenmeli.
4. **Trend performansı.** Milyonlarca bulguda `findings_daily` gibi bir özet tablosu ya da materialized view gerekebilir.
5. **CPE AND konfigürasyonları** ve **distro backport'ları** kaynaklı yanlış pozitifler.
6. **CVE ignore / VEX.**
7. **UI otomatik testleri** (Vitest ve Playwright).

## 11. Test
- **Unit:** sürüm karşılaştırma, imaj referansı, aralık eşleştirme, CVSS v3, NVD/OSV dönüşümleri, merge, owner çözümü, rapor oluşturma ve gönderme, envanter doğrulama ve fingerprint, matcher.
- **PostgreSQL entegrasyon testleri** (`TEST_DATABASE_URL`; tanımlı değilse atlanır):
  - migration'ın tekrar çalıştırılabilirliği,
  - ingest ve uzlaştırma: açılma, kapanma, değişmeyen rapor,
  - feed değişince yeniden eşleştirme,
  - feed'den ürün çıkarılması,
  - tüm okuma sorguları: filtre, sıralama, sayfalama,
  - geçmiş, cluster silme, budama,
  - feed sync: ETag'siz sunucuda değişmeyen feed'in algılanması, checksum hatasında eski verinin korunması.
- CI'da `postgres:18.6-alpine` servis container'ı ile `go test -race -p 1` çalışır. `-p 1` gerekli, çünkü veritabanı kullanan paketler aynı test veritabanını paylaşıyor.
- **Elle uçtan uca (yapıldı):**
  - Yerel: dev PostgreSQL + API + agent (`kind-backend`) + Vite UI.
  - Geçici bir kind cluster'ında `helm install` (bundled PG): API'nin veritabanını beklemesi, migration, host'tan feed sync, agent'ın tekrar deneyip rapor göndermesi, UI proxy'sinin POST'u 403 ile reddetmesi, `helm upgrade` sonrasında secret'ların korunması.
- **Helm:** chart `huseyinbabal/charts`'a taşınırken lint, dört kurulum modunun render edilmesi ve geçersiz ayarların reddedilmesi yerelde kontrol edildi.
