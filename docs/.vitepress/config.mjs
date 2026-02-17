import { defineConfig } from 'vitepress'

export default defineConfig({
  title: "AegisFlow",
  description: "The Universal Security Layer for AI Agents",
  themeConfig: {
    logo: 'https://raw.githubusercontent.com/Arigitshub/AegisFlow/main/docs/public/logo.png', // Placeholder or use emoji in title
    nav: [
      { text: 'Guide', link: '/guide/introduction' },
      { text: 'Core Concepts', link: '/core/detection-engine' },
      { text: 'Cookbook', link: '/cookbook/ollama-guardian' },
      { text: 'API', link: '/api/python-sdk' }
    ],
    sidebar: [
      {
        text: 'Guide',
        items: [
          { text: 'Introduction', link: '/guide/introduction' },
          { text: 'Installation', link: '/guide/installation' },
          { text: 'Quickstart', link: '/guide/quickstart' },
          { text: 'Configuration', link: '/guide/configuration' }
        ]
      },
      {
        text: 'Core Concepts',
        items: [
          { text: 'Detection Engine', link: '/core/detection-engine' },
          { text: 'The Sandwich', link: '/core/sandwich' },
          { text: 'Sentinel State', link: '/core/sentinel' },
          { text: 'Rail System', link: '/core/rails' }
        ]
      },
      {
        text: 'Cookbook',
        items: [
          { text: 'Ollama Guardian', link: '/cookbook/ollama-guardian' },
          { text: 'LangChain Integration', link: '/cookbook/langchain' },
          { text: 'Custom Plugins', link: '/cookbook/custom-plugins' }
        ]
      },
      {
        text: 'API Reference',
        items: [
            { text: 'Python SDK', link: '/api/python-sdk' }
        ]
      }
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/Arigitshub/AegisFlow' }
    ],
    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2026 AegisFlow Security'
    }
  }
})
