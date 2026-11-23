// @ts-check
import starlight from '@astrojs/starlight'
import { defineConfig } from 'astro/config'

// Published to GitHub Pages as a project site.
export default defineConfig({
  site: 'https://huseyinbabal.github.io',
  base: '/cvedetector',
  integrations: [
    starlight({
      title: 'cvedetector',
      description: 'Known CVEs in the container images running in your Kubernetes clusters, without scanning.',
      logo: { src: './src/assets/logo.svg' },
      favicon: '/favicon.svg',
      customCss: ['@fontsource-variable/geist', './src/styles/custom.css'],
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/huseyinbabal/cvedetector' }],
      editLink: { baseUrl: 'https://github.com/huseyinbabal/cvedetector/edit/main/docs/' },
      lastUpdated: true,
      sidebar: [
        {
          label: 'Getting started',
          items: [
            { label: 'Quick start', slug: 'getting-started/quick-start' },
            { label: 'Kubernetes', slug: 'getting-started/kubernetes' },
            { label: 'Configuration', slug: 'getting-started/configuration' },
          ],
        },
        {
          label: 'Features',
          items: [
            { label: 'Overview', slug: 'features/overview' },
            { label: 'Images and workloads', slug: 'features/images-and-workloads' },
            { label: 'Vulnerabilities', slug: 'features/vulnerabilities' },
            { label: 'Coverage gaps', slug: 'features/coverage-gaps' },
            { label: 'Multiple clusters', slug: 'features/multiple-clusters' },
            { label: 'Monitoring and alerts', slug: 'features/monitoring' },
          ],
        },
        {
          label: 'Guides',
          items: [
            { label: 'Add a product to the feed', slug: 'guides/add-a-product' },
            { label: 'Development', slug: 'guides/development' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'How matching works', slug: 'reference/matching' },
            { label: 'The feed', slug: 'reference/feed' },
            { label: 'HTTP API', slug: 'reference/api' },
            { label: 'Architecture', slug: 'reference/architecture' },
          ],
        },
      ],
    }),
  ],
})
