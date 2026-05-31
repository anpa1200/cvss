// @ts-check
const { themes: prismThemes } = require('prism-react-renderer');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'CVSS v4.0 Field Guide',
  tagline: 'The Practical Field Guide for Vulnerability Management',
  favicon: 'img/favicon.ico',

  url: 'https://anpa1200.github.io',
  baseUrl: '/cvss/',

  organizationName: 'anpa1200',
  projectName: 'cvss',

  headTags: [
    {
      tagName: 'script',
      attributes: {
        async: 'true',
        src: 'https://www.googletagmanager.com/gtag/js?id=G-TMTG21RVHM',
      },
    },
    {
      tagName: 'script',
      attributes: {},
      innerHTML: `
        window.dataLayer = window.dataLayer || [];
        function gtag(){dataLayer.push(arguments);}
        gtag('js', new Date());
        gtag('config', 'G-TMTG21RVHM');
      `,
    },
  ],
  trailingSlash: false,

  onBrokenLinks: 'throw',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  markdown: {
    format: 'detect',
    hooks: {
      onBrokenMarkdownLinks: 'throw',
    },
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: './sidebars.js',
          routeBasePath: 'docs',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      colorMode: {
        defaultMode: 'dark',
        disableSwitch: false,
        respectPrefersColorScheme: false,
      },
      announcementBar: {
        id: 'auth_banner',
        content: 'All scoring examples use publicly available CVE data from NVD, FIRST.org, and CISA KEV. Always validate scores against your own environment.',
        backgroundColor: '#1a1a2e',
        textColor: '#e94560',
        isCloseable: true,
      },
      navbar: {
        logo: {
          alt: 'Site logo',
          src: 'img/logo.png',
        },
        title: 'CVSS v4.0 Field Guide',
        items: [
          {
            type: 'docSidebar',
            sidebarId: 'tutorialSidebar',
            position: 'left',
            label: 'Guide',
          },
          {
            href: 'https://medium.com/@1200km',
            label: 'Medium',
            position: 'right',
          },
          {
            href: 'https://github.com/anpa1200/cvss',
            label: 'GitHub',
            position: 'right',
          },
          {
            href: 'https://anpa1200.github.io/',
            label: 'Main Page',
            position: 'right',
            className: 'navbar-portfolio-btn',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Guide',
            items: [
              { label: 'Introduction', to: '/docs/introduction' },
              { label: 'Vector String', to: '/docs/vector-string' },
              { label: 'Worked Examples', to: '/docs/worked-examples' },
              { label: 'Cheatsheet', to: '/docs/cheatsheet' },
            ],
          },
          {
            title: 'Author',
            items: [
              { label: 'Medium', href: 'https://medium.com/@1200km' },
              { label: 'LinkedIn', href: 'https://linkedin.com/in/andrey-pautov' },
              { label: 'GitHub', href: 'https://github.com/anpa1200' },
            ],
          },
          {
            title: 'Resources',
            items: [
              { label: 'FIRST.org CVSS Calculator', href: 'https://www.first.org/cvss/calculator/4-0' },
              { label: 'CISA KEV Catalog', href: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
              { label: 'EPSS', href: 'https://www.first.org/epss/' },
            ],
          },
        ],
        copyright: `© ${new Date().getFullYear()} Andrey Pautov · <a href="https://www.paypal.com/donate/?business=W3XDKS7J9XTCG&no_recurring=0&item_name=Buy+me+a+coffee+%28PayPal%29+%E2%80%94+Keep+the+lab+running&currency_code=USD" target="_blank" rel="noopener noreferrer">Buy me a coffee</a>`,
      },
      prism: {
        theme: prismThemes.dracula,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ['python', 'bash', 'json'],
      },
    }),
};

module.exports = config;
