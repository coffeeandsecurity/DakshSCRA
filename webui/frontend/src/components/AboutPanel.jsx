function AboutRow({ label, children }) {
  return (
    <div className="help-about-row">
      <span className="help-about-label">{label}</span>
      <div className="about-inline-value">{children}</div>
    </div>
  )
}

function AboutCard({ title, children }) {
  return (
    <section className="help-section about-section-card">
      <h2 className="help-h2">{title}</h2>
      {children}
    </section>
  )
}

export default function AboutPanel() {
  return (
    <div className="about-page">
      <div className="help-content-inner about-content-inner">
        <div className="help-header">
          <h1 className="help-title">About DakshSCRA</h1>
          <p className="help-subtitle">
            Background, release history, author details, and the motivation behind the project.
          </p>
        </div>

        <AboutCard title="Overview">
          <p className="help-p">
            DakshSCRA was built as a structured source code review assistant for complex manual security reviews.
            It is designed to help reviewers move beyond ad hoc pattern searching and toward a more systematic,
            coverage-oriented review process across large codebases, multiple platforms, and diverse frameworks.
          </p>
          <p className="help-p">
            The project was started by <strong>Debasis Mohanty</strong> after many years of using a mix of manual
            review methods and custom scripting during real-world source code review engagements. The goal was not
            simply to build another pattern-matching scanner, but to create a flexible code review tool that could
            guide both reviewers and developers through a structured and holistic analysis workflow.
          </p>
        </AboutCard>

        <AboutCard title="Why It Was Built">
          <p className="help-p">
            Debasis has been performing code reviews for more than two decades across a wide range of platforms,
            frameworks, and architectures. That experience made one point clear: source code review is tedious,
            mentally demanding, and often difficult to scale when an application becomes large, distributed, or
            highly customized.
          </p>
          <p className="help-p">
            Over time, experienced reviewers learn that the only reliable way to maintain depth and coverage is to
            structure the review and follow a systematic approach. DakshSCRA was created from that idea. The tool is
            intended to support disciplined review methodology by surfacing areas of interest, organizing evidence,
            and performing advanced analysis that helps reviewers focus on what matters most.
          </p>
          <p className="help-p">
            Another motivation was the gap in the tooling market. Commercial products that perform strong taint
            analysis with real control-flow and data-flow tracing are often expensive niche offerings. Many open-source
            alternatives either stop at pattern checks or require heavy customization while still leaving major
            coverage gaps. DakshSCRA was written to set a much higher standard for open-source code review tooling,
            while keeping the architecture flexible enough to support deeper and broader review use cases.
          </p>
        </AboutCard>

        <AboutCard title="History">
          <div className="about-timeline">
            <div className="about-timeline-item">
              <div className="about-timeline-date">Black Hat USA 2022</div>
              <div className="about-timeline-body">
                DakshSCRA was first introduced privately during the secure code review training
                <strong> Source Code Review (Raise Your Bar Beyond Grep)</strong>. It was shown to trainees as part
                of the review methodology and supporting workflow, after having been kept private for years.
              </div>
            </div>
            <div className="about-timeline-item">
              <div className="about-timeline-date">Black Hat USA 2023 Arsenal</div>
              <div className="about-timeline-body">
                DakshSCRA made its official public debut as an open-source tool demonstration. This was the point at
                which the project moved from a private capability into a public release.
              </div>
            </div>
            <div className="about-timeline-item">
              <div className="about-timeline-date">Public Release</div>
              <div className="about-timeline-body">
                After the Black Hat USA 2023 Arsenal debut, the project was made publicly available on GitHub so the
                wider community could use it, study it, and contribute to its continued evolution.
              </div>
            </div>
          </div>
        </AboutCard>

        <AboutCard title="Project Direction">
          <p className="help-p">
            The long-term direction of DakshSCRA is to remain a structured and systematic code review companion rather
            than a shallow alert generator. It aims to guide both developers and reviewers with areas of interest,
            advanced analysis, extensible rule logic, wide platform and framework coverage, and reporting that helps
            explain why something matters.
          </p>
          <p className="help-p">
            A central design goal has always been flexibility. The architecture is meant to be extensible so the tool
            can be adapted to different review styles, technologies, and depth requirements without forcing users into
            a narrow scanner-only model.
          </p>
          <p className="help-p">
            The broader objective is straightforward: provide a serious open-source code review tool without the
            ridiculous licensing costs typically associated with advanced commercial offerings, while continuing to push
            distinctive capabilities that raise the bar for what open-source review tooling can do.
          </p>
        </AboutCard>

        <AboutCard title="Author Details">
          <div className="help-about-card">
            <AboutRow label="Author">Debasis Mohanty</AboutRow>
            <AboutRow label="Website">
              <a className="help-about-link" href="https://www.coffeeandsecurity.com" target="_blank" rel="noreferrer">
                coffeeandsecurity.com
              </a>
            </AboutRow>
            <AboutRow label="Email">
              <a className="help-about-link" href="mailto:d3basis.m0hanty@gmail.com">
                d3basis.m0hanty@gmail.com
              </a>
            </AboutRow>
            <AboutRow label="Twitter / X">
              <a className="help-about-link" href="https://x.com/coffeensecurity" target="_blank" rel="noreferrer">
                @coffeensecurity
              </a>
            </AboutRow>
            <AboutRow label="GitHub">
              <a className="help-about-link" href="https://github.com/coffeeandsecurity/DakshSCRA" target="_blank" rel="noreferrer">
                github.com/coffeeandsecurity/DakshSCRA
              </a>
            </AboutRow>
            <AboutRow label="License">
              <span className="about-inline-text">GNU General Public License v3.0 (GPL-3.0)</span>
            </AboutRow>
          </div>
          <div className="help-callout help-callout-tip about-highlight-note">
            <div className="about-highlight-copy">
              If DakshSCRA has helped your team save significant time, effort, or cost, reduced dependence on expensive
              commercial tools, improved review coverage, or made code review more structured and effective, feel free
              to reach out and share your experience. I am always open to thoughtful feedback and interesting conversations.
            </div>
          </div>
        </AboutCard>
      </div>
    </div>
  )
}
