import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import styles from './index.module.css';

const SECTIONS = [
  {
    num: '01', emoji: '📖', title: 'Introduction',
    desc: 'Why Base scores are wrong 95% of the time — and what CVSS v4.0 does to fix it.',
    to: '/docs/introduction',
    links: [{ label: 'CVSS Is a Tool, Not a Score', to: '/docs/introduction' }, { label: 'What Changed in v4.0', to: '/docs/introduction#what-changed-in-v40--and-why-it-matters' }],
  },
  {
    num: '02', emoji: '⚖️', title: 'v3.1 vs v4.0',
    desc: 'Same CVEs, side-by-side. Log4Shell, PrintNightmare, local privesc — see exactly where scores differ and why.',
    to: '/docs/v3-vs-v4',
    links: [{ label: 'Comparison Table', to: '/docs/v3-vs-v4' }],
  },
  {
    num: '03', emoji: '🔬', title: 'Vector String & Metrics',
    desc: 'Full anatomy of the CVSS v4.0 vector string. Every metric explained with practical decision rules.',
    to: '/docs/vector-string',
    links: [{ label: 'Vector Anatomy', to: '/docs/vector-string' }, { label: 'Metric Groups', to: '/docs/vector-string#group-1-base-metrics-set-by-vendor' }],
  },
  {
    num: '04', emoji: '🔄', title: 'Scoring Lifecycle',
    desc: 'CVSS-B → CVSS-BT → CVSS-BTE. How scores mature from vendor publication to your environment.',
    to: '/docs/lifecycle',
    links: [{ label: 'B → BT → BTE', to: '/docs/lifecycle' }, { label: 'Scoring Workflow', to: '/docs/lifecycle' }],
  },
  {
    num: '05', emoji: '🎯', title: 'Threat & Environmental',
    desc: 'KEV, EPSS, Metasploit, ExploitDB. Set E:U vs E:A vs E:P with confidence. Override Base with your reality.',
    to: '/docs/threat-metrics',
    links: [{ label: 'Exploit Maturity', to: '/docs/threat-metrics' }, { label: 'Environmental Overrides', to: '/docs/threat-metrics' }],
  },
  {
    num: '06', emoji: '🧪', title: 'Worked Examples',
    desc: 'Log4Shell, Erlang/OTP CVE-2025-32433, 18-Critical firmware report, CitrixBleed, MOVEit, FortiOS.',
    to: '/docs/worked-examples',
    links: [{ label: 'Log4Shell 72h', to: '/docs/worked-examples' }, { label: 'Firmware Report', to: '/docs/worked-examples' }, { label: 'CitrixBleed', to: '/docs/worked-examples' }],
  },
  {
    num: '07', emoji: '🏥', title: 'Industry-Specific Scoring',
    desc: 'Healthcare (HIPAA), Finance (PCI-DSS), OT/ICS (ISA/IEC 62443). Environmental profiles per sector.',
    to: '/docs/industry-specific',
    links: [{ label: 'Healthcare', to: '/docs/industry-specific' }, { label: 'OT/ICS', to: '/docs/industry-specific' }],
  },
  {
    num: '08', emoji: '🗂️', title: 'CVSS vs SSVC',
    desc: 'When CVSS is the right tool and when SSVC gives a better answer. Decision framework for VM programs.',
    to: '/docs/cvss-vs-ssvc',
    links: [{ label: 'Comparison', to: '/docs/cvss-vs-ssvc' }],
  },
  {
    num: '09', emoji: '⚙️', title: 'Practical VM Workflow',
    desc: 'End-to-end: scanner output → CVSS-B → CVSS-BT → CVSS-BTE → SLA assignment → ticket.',
    to: '/docs/vm-workflow',
    links: [{ label: '6-Step Workflow', to: '/docs/vm-workflow' }],
  },
  {
    num: '10', emoji: '🛠️', title: 'Enrichment Tool',
    desc: 'Python CLI that pulls KEV, EPSS, NVD, Metasploit, and ExploitDB to auto-enrich CVSS scores.',
    to: '/docs/enrichment-tool',
    links: [{ label: 'Tool Overview', to: '/docs/enrichment-tool' }],
  },
  {
    num: '11', emoji: '📋', title: 'Regulatory Evidence',
    desc: '5-Phase CVSS Maturity Model. Using CVSS-BTE as auditable evidence for NIS2, PCI-DSS, HIPAA, NERC CIP — not CVSS as a framework.',
    to: '/docs/regulatory',
    links: [{ label: '5-Phase Model', to: '/docs/regulatory' }, { label: 'Supplemental Metrics', to: '/docs/regulatory' }],
  },
  {
    num: '12', emoji: '⚠️', title: 'Common Mistakes & Interview Q&A',
    desc: 'The 8 most common CVSS errors — and 6 interview questions that separate practitioners from readers.',
    to: '/docs/mistakes',
    links: [{ label: '8 Mistakes', to: '/docs/mistakes' }, { label: 'Interview Q&A', to: '/docs/mistakes' }],
  },
  {
    num: '13', emoji: '📌', title: 'Cheatsheet & Tools',
    desc: 'Quick-reference cards, SLA tiers, all metric values, FIRST.org calculator, KEV API, EPSS API.',
    to: '/docs/cheatsheet',
    links: [{ label: 'Cheatsheet', to: '/docs/cheatsheet' }, { label: 'Tools & Resources', to: '/docs/cheatsheet' }],
  },
];

export default function Home() {
  const { siteConfig } = useDocusaurusContext();

  return (
    <Layout
      title="CVSS v4.0 Field Guide"
      description="The Practical Field Guide for Vulnerability Management — from Base scores to fully enriched CVSS-BTE. Real CVEs, real workflows, enrichment tool included."
    >
      {/* ── HERO ──────────────────────────────────────────────────── */}
      <section className={styles.hero}>
        <div className={styles.heroInner}>
          <div className={styles.badge}>
            <span className={styles.badgeDot} />
            CVSS v4.0 · FIRST.org · KEV · EPSS · Enrichment Tool
          </div>

          <h1 className={styles.heroTitle}>
            <span>CVSS v4.0</span>
            <br />
            The Practical Field Guide
          </h1>

          <p className={styles.heroSubtitle}>
            From a number nobody trusts to a tool that changes how you work.
            Base scores → Threat enrichment → Environmental context → Prioritized action.
          </p>

          <div className={styles.ctaRow}>
            <Link className={styles.btnPrimary} to="/docs/introduction">
              ▶ Start Reading
            </Link>
            <Link className={styles.btnSecondary} to="/docs/worked-examples">
              🧪 Worked Examples
            </Link>
            <Link className={styles.btnSecondary} to="/docs/cheatsheet">
              📌 Cheatsheet
            </Link>
          </div>

          <div className={styles.stats}>
            {[
              { num: '13',  label: 'Chapters' },
              { num: '4',   label: 'Worked CVEs' },
              { num: '31',  label: 'Infographics' },
              { num: '8',   label: 'Common Mistakes' },
            ].map((s) => (
              <div key={s.label} className={styles.statItem}>
                <span className={styles.statNum}>{s.num}</span>
                <span className={styles.statLabel}>{s.label}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── SCORE REFERENCE STRIP ─────────────────────────────────── */}
      <section className={styles.scoreStrip}>
        <div className={styles.scoreGrid}>
          {[
            { range: '9.0–10.0', sev: 'Critical', sla: '24–72 hours', cls: 'critical' },
            { range: '7.0–8.9',  sev: 'High',     sla: '30-day SLA',  cls: 'high'     },
            { range: '4.0–6.9',  sev: 'Medium',   sla: '90-day SLA',  cls: 'medium'   },
            { range: '0.1–3.9',  sev: 'Low',      sla: 'Next cycle',  cls: 'low'      },
          ].map((s) => (
            <div key={s.sev} className={styles.scoreCard}>
              <div className={`${styles.scoreRange} ${styles[s.cls]}`}>{s.range}</div>
              <div className={`${styles.scoreSev} ${styles[s.cls]}`}>{s.sev}</div>
              <div className={styles.scoreSla}>{s.sla}</div>
            </div>
          ))}
        </div>
      </section>

      {/* ── AUTHOR ────────────────────────────────────────────────── */}
      <section className={styles.authorSection}>
        <div className="container">
          <div className={styles.authorCard}>
            <div className={styles.authorInfo}>
              <p className={styles.sectionLabel}>The Author</p>
              <h2>Andrey Pautov</h2>
              <p className={styles.authorBio}>
                CTI researcher with a strong background in offensive security, vulnerability management,
                and AI-driven attack simulation. Focused on adversary profiling, detection engineering,
                and translating vulnerability data into prioritized operational decisions.
                All scoring examples use publicly available CVE data from NVD, FIRST.org, and CISA KEV.
              </p>
              <div className={styles.authorLinks}>
                <a href="https://medium.com/@1200km" target="_blank" rel="noopener noreferrer" className={styles.authorLink}>Medium</a>
                <a href="https://linkedin.com/in/andrey-pautov" target="_blank" rel="noopener noreferrer" className={styles.authorLink}>LinkedIn</a>
                <a href="https://github.com/anpa1200" target="_blank" rel="noopener noreferrer" className={styles.authorLink}>GitHub</a>
                <a href="mailto:1200km@gmail.com" className={styles.authorLink}>Email</a>
              </div>
            </div>
            <div className={styles.authorDonate}>
              <p className={styles.donateText}>If this guide saves you time or improves your VM program —</p>
              <a
                href="https://www.paypal.com/donate/?business=W3XDKS7J9XTCG&no_recurring=0&item_name=Buy+me+a+coffee+%28PayPal%29+%E2%80%94+Keep+the+lab+running&currency_code=USD"
                target="_blank" rel="noopener noreferrer"
                className={styles.donateBtn}
              >
                ☕ Buy Me a Coffee
              </a>
              <p className={styles.donateNote}>Keep the research going</p>
            </div>
          </div>
        </div>
      </section>

      {/* ── CHAPTERS GRID ─────────────────────────────────────────── */}
      <section className={styles.sectionsArea}>
        <div className="container">
          <p className={styles.sectionLabel}>Guide Contents</p>
          <h2 className={styles.sectionTitle}>13 chapters, zero fluff</h2>
          <p className={styles.sectionSubtitle}>
            Every chapter is built around a real operational decision —
            not theory, not vendor marketing.
          </p>
          <div className={styles.sectionsGrid}>
            {SECTIONS.map((s) => (
              <Link key={s.num} className={styles.sectionCard} to={s.to}>
                <div className={styles.sectionCardTop}>
                  <span className={styles.sectionCardEmoji}>{s.emoji}</span>
                  <div>
                    <div className={styles.sectionCardNum}>{s.num}</div>
                    <h3>{s.title}</h3>
                  </div>
                </div>
                <p>{s.desc}</p>
                <div className={styles.sectionCardLinks}>
                  {s.links.map((l) => (
                    <span key={l.label} className={styles.sectionCardLink}>{l.label}</span>
                  ))}
                </div>
              </Link>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA ───────────────────────────────────────────────────── */}
      <section className={styles.ctaBanner}>
        <div className="container">
          <h2>Stop sorting by score. Start prioritizing by risk.</h2>
          <p>The complete CVSS v4.0 workflow — from scanner CSV to enriched, actionable findings.</p>
          <div className={styles.ctaRow}>
            <Link className={styles.btnPrimary} to="/docs/introduction">
              ▶ Read the Guide
            </Link>
            <Link className={styles.btnSecondary} to="/docs/enrichment-tool">
              🛠️ Enrichment Tool
            </Link>
          </div>
        </div>
      </section>
    </Layout>
  );
}
