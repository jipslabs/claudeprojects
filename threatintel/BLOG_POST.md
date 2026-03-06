# I Built a Threat Intelligence Service Without Writing a Single Line of Code

**OPINION | TECHNOLOGY & CYBERSECURITY**

*By Jiphun Satapathy*

---

In my years of working in tech, one pattern has never changed: engineers hate doing the same thing again and again. The mantra is simple, anything you do more than three times should be automated. It's exactly why coding assistants have become one of the most adopted AI use cases in the industry.

But every so often, a shift in tech is so profound that it stops feeling like a better tool and starts feeling like a new era entirely. Mobile did it. IoT did it. Cloud did it. Each one fundamentally changed the rules of the game.

**Claude Code and Claude Code Security feels like that moment. And honestly, it feels bigger.**

---

## A Quick Confession

I'll be honest. I have more AI subscriptions than I need. ChatGPT, Claude, Cursor, Replit, AWS, Lovable. The usual suspects. But I'm an engineer at heart, so I like to get my hands dirty and like to get a first hand experience when there is so much talk about a new tech. So I decided to put Claude Code to the test with a real challenge.


## The Challenge: A Threat Intel Service, Zero Code Written by Me

My goal was straightforward:

> **Build a functioning local threat intelligence service using Claude Code — no IDE, no manual coding, start to finish.**

The service needed to:
- Pull threat intelligence and security news from **15+ public sources**
- Cover recent CVEs, known exploits, and breach reports
- Generate a structured report every week, stored locally
- Run on my personal laptop with **zero ongoing cloud cost or subscription**

The entire codebase is public: [github.com/jipslabs/claudeprojects](https://github.com/jipslabs/claudeprojects)

---

## How I Did It: Step by Step

### Step 1 — Write the PRD

I used ChatGPT to draft a Product Requirements Document for the service, then tweaked it to match my goals. (No deep reason for using ChatGPT here, just familiarity. I could have used Claude just as easily.) I made a few changes around manual trigger vs. automated scheduling and confirmed Python as the primary language.

### Step 2 — Hand It to Claude Code

I opened Claude Code, created a project, pointed it at the PRD, and told it to build.

It showed me every major step it was taking in real time — decisions, trade-offs, file structure. When it was done, it had built and committed a complete project to my GitHub repo:

```
cyberbulletin/
├── config.yaml          # 15+ sources, watchlist, scoring weights
├── pyproject.toml       # pip-installable, secnews CLI entrypoint
├── secnews/
│   ├── cli/
│   │   ├── main.py      # argparse: --hours, --min-score, --filter
│   │   └── display.py   # Rich output: severity badges, clusters, color scoring
│   ├── core/
│   │   ├── models.py    # NewsItem + Cluster dataclasses
│   │   ├── dedup.py     # SHA-256 fingerprint + rapidfuzz fuzzy dedup (85% threshold)
│   │   ├── cluster.py   # Union-find keyword clustering (2+ shared keywords)
│   │   └── scorer.py    # 0–100 heuristic: CVSS + recency decay + tier + HN + watchlist
│   └── sources/
│       ├── fetcher.py   # ThreadPoolExecutor parallel dispatch
│       ├── rss.py       # RSS/Atom (blogs, threat intel, community)
│       ├── nvd.py       # NVD CVE API v2
│       ├── osv.py       # OSV.dev (7 ecosystems)
│       ├── hn.py        # HackerNews Firebase API (security-filtered)
│       ├── cisa.py      # CISA Known Exploited Vulnerabilities catalog
│       └── json_feed.py # Generic JSON fallback
└── tests/               # 25 passing unit tests
```

### Step 3 — Run It (Without Following the Instructions)

Claude Code suggested running `pip install -e .` and then `secnews`.

I didn't follow that instruction. I just asked Claude Code to run it for me.

**It did exactly that.** First run:
- **94 items fetched** from 10 sources in parallel
- **69 deduplicated/filtered** (score < 40 or fuzzy duplicates removed)
- **25 items surfaced**, grouped into clusters

Two sources had issues — Google Project Zero's FeedBurner URL was dead (404), and OSV.dev's `/query` endpoint required a package name field. I typed "yes" when Claude Code asked if it should fix them. Two minutes later, both were fixed and pushed.

---

## Adding Intelligence: From Regex to AI

At this point, the service was working — but it was entirely **heuristic**. Pattern matching. Regex-based classification. No real understanding.

I asked Claude Code where AI would make the biggest difference. It identified four areas:

| Area | Current Limitation | AI Fix |
|---|---|---|
| **Incident field extraction** | Regex misses nuanced phrasing | LLM extracts structured fields with near-perfect accuracy |
| **Deduplication** | Fuzzy string match breaks on different wording | Embeddings catch semantic duplicates |
| **Scoring & relevance** | Pure math — keyword counting | LLM understands *why* something matters to *your* environment |
| **Clustering** | Keyword overlap only | Embeddings group semantically related stories |

To illustrate the gap between regex and AI, Claude Code showed me this side-by-side:

**Current (regex):**
```
Title: "Salt Typhoon's US telecom breach accessed private communications"
Victim: Unknown  ← missed because pattern didn't match
Impact: Not reported  ← missed "private communications"
```

**With LLM:**
```
Victim: US Telecom carriers (AT&T, Verizon, T-Mobile)
Impact: Private communications of government officials intercepted
Root cause: Nation-state persistent access via unpatched network gear
Fixed: No
```

The difference is stark. I asked about cost for running this daily with the Anthropic API.

**Monthly Cost Estimate using Claude Haiku:**

| Usage | Items/day | Daily cost | Monthly cost |
|---|---|---|---|
| Conservative | 20 incidents | $0.013 | ~$0.40 |
| Typical | 40 incidents | $0.026 | ~$0.79 |
| Heavy | 80 incidents | $0.052 | ~$1.57 |

Under $2/month for daily AI-powered threat intelligence. I went with Anthropic.

---

## The Security Scan: Because I'm a Security Person

I asked Claude Code to run a security scan of the repository using its Code Security feature.

It came back with a categorized report:

| Severity | Count |
|---|---|
| 🔴 High | 5 |
| 🟠 Medium | 6 |
| 🟡 Low/Info | 4 |

Issues included zip slip vulnerabilities, prompt injection risks, missing redirect limits, and loose API error logging. Real findings, not noise.

I asked Claude Code to fix them. It did. To verify, I ran the same code through **Codex** independently — both came back clean (ignored informational and lows) after the fixes were applied.

Then I ran the security scan a second time with Claude Code. Clean report.

---

## The Output: What It Actually Produces

With the full AI-enhanced stack running, the service surfaced **31 incidents** with structured intelligence cards. Here's a sample:

```
#1  🔓 Authentication Bypass   Score: 80   ✦ AI   6d ago

  What happened    [CISA KEV] CVE-2026-20127 — Cisco Catalyst SD-WAN
                   Authentication Bypass Vulnerability

  Who was affected Cisco Catalyst SD-WAN Controller and Manager [CVE-2026-20127]

  Impact           Not reported

  Root cause       CVE-2026-20127 — improper peering authentication mechanism
                   allowing unauthenticated remote attackers to bypass
                   authentication and obtain administrative privileges

  Fixed?           YES — Patch Available

  AI Analysis      An actively exploited authentication bypass in critical Cisco
                   SD-WAN infrastructure allows unauthenticated remote attackers
                   to gain administrative access, requiring immediate patching
                   by 2026-02-27.

  Source           CISA Known Exploited Vulnerabilities
```


---

## Gaps in this service

This is by no means an enterprise ready product. There are many additional layers required before a service like this can be considered enterprise ready.

For example, areas such as user identity and access management, payment and billing infrastructure, integration with non-public intelligence sources, deeper threat research capabilities, and enterprise-specific context would all need to be incorporated. These elements are essential for building a robust and reliable service that enterprises can trust.

That said, the foundation is already there. What remains is largely a matter of human imagination combined with thoughtful design and the ability to guide AI through the right prompts to build and integrate these additional layers. 

## What This Actually Means for Cybersecurity

The headline question everyone is asking: *Will AI security tools end the cybersecurity industry?*

Honestly? Nobody knows for certain and it doesn't matter. Every business owner remains paranoid regardless. Here's what I believe:

As long as digital information and sensitive data exist, privacy is valued, regulations are implemented cybersecurity will exist. The players may change. The tools will definitely change. But the need won't disappear.

**What I do think will happen over the years:**

- **The productivity leap is real.** Something that would have taken a team weeks now takes hours to days. That changes the economics of every security product.
- **The entire SDLC will reshape itself** to match the speed of AI-assisted development. Waterfall or the traditional agile development thinking won't survive. Scrutiny on quality, functionality and security needs complete over-haul.
- **Development costs will drop dramatically.** Companies won't pass all of those savings to customers, they'll expand their feature set faster. Expand to other verticals quicker. You no longer need to be a multi-billion dollar company to build like one.
- **Digitization will accelerate in healthcare, industrial, and transportation.** More digital surfaces mean more attack surface. More scope for cybersecurity — not less.
- **Robotics will explode.** Cybersecurity and privacy will be mission-critical for physical systems in ways we're only beginning to think about.
- **Consolidation is coming.** M&A activity for point solutions will accelerate. Siloed tools that don't plug into AI-native workflows will become acquisition targets or irrelevant.
- **Data will continue to be a significant differnetiator.** If a non cyber company can build a top notch LLM model, nothing prevents a top cyber company to do the same. The cyber companies will have a massive benefit of enterprise data that they can leverage. They don't have to train their models with this data. They can still provide custom features to their customers. .


---

## Advice for Security Leaders

**Stop underestimating AI in security.** As Reid Hastings writes in *Superagency*, start asking what can go right with AI, not just what can go wrong. I still hear fellow CISOs expressing doubt and a lack of trust. Yes, there are risks and trust issues with AI. However, don't get hung up on those risks. Avoide misplaced paranoia and figure out how the world is solving those challenges. That skepticism, left unchecked, becomes a competitive liability. 

**Be hands-on.** You need to know what's actually possible. Open these tools to your engineers and practitioners. Don't leave it to good intentions, require it.

**Be patient with the outcomes, but not with the adoption.** AI is the fastest path to demonstrating value that I've seen in two decades. Give your teams the freedom to explore it. It's okay if you don't have strong signals to demonstrate ROI just yet.

---

## Advice for Anyone wanting to building a Career in Cybersecurity or Tech

Build something every day. Even if no one is paying you. Even if it's small. Publish it proudly.

Every resume should now carry a link to a GitHub or a working app that demonstrates what you've built using AI tools and what real problem it solves. If that work is tailored to the company and the business you're applying to, it will be more influential than any certification or degree.

The bar for demonstrating capability has never been lower. The bar for standing out has never been higher. Those two facts point in the same direction: **build, ship, show your work and iterate**

## Conclusion

The breakthroughs we see today in technology and cybersecurity are not magic. They are the result of decades of progress, built by countless engineers, researchers, and builders pushing the boundaries of what is possible.

I feel fortunate to have witnessed and been part of some of these moments of transformation. I started my career writing programs in C (Dennis Ritchie’s The C Programming Language still sits on my bookshelf). From those early days of system level programming to today’s world of AI-driven systems, the pace of innovation has been remarkable.

The future will continue to evolve in ways we cannot fully predict, as it always has. But moments like this create opportunity. Instead of resisting change, we should strive to understand it, challenge it, shape it, and ultimately ride the wave of innovation.

After all, there are still far too many problems in the world waiting to be solved.

---

*The full source code for the threat intelligence service described in this post is available at [github.com/jipslabs/claudeprojects](https://github.com/jipslabs/claudeprojects). Setup instructions are in the README.*
