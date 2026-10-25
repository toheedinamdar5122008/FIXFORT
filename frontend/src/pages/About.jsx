import React, { useState } from 'react'
import { Reveal } from '../ui.jsx'
import ShieldAssembly from '../ShieldAssembly.jsx'

const PRINCIPLES = [
  ['The AI suggests', 'An engine proposes a temporary shield rule for one specific finding — never a blanket, generic firewall.'],
  ['The Practice Room proves', 'Every rule is tested in an isolated sandbox against real attacks AND real users before it can go live. Proof, not trust.'],
  ['The human decides', 'Nothing is deployed automatically. A person approves the proven rule — the AI can never act alone.'],
  ['Nothing stays temporary forever', 'When the permanent fix is verified, FixFort retires its own rule. Protections never pile up.'],
]

export default function About() {
  const [step, setStep] = useState(0)
  return <div className="wrap">
    <Reveal><span className="eyebrow">Mission</span>
      <h1 className="misslead">We protect the gap between<br/>a vulnerability found<br/>and a vulnerability fixed.</h1>
    </Reveal>

    <Reveal className="missgap" delay={120}>
      <div className="missstep rd"><span>Vulnerability found</span><b>Day 0</b></div>
      <div className="missarrow">the dangerous gap — days to weeks</div>
      <div className="missstep gn"><span>Vulnerability fixed</span><b>Day 12+</b></div>
      <p className="note missgap-cap">For that entire window the site is exposed. FixFort stands in it — protected in minutes, proven safe, removed once the real fix lands.</p>
    </Reveal>

    <Reveal><h2 className="misssub">Four principles — and how the shield comes together</h2></Reveal>
    <div className="missassembly">
      <ol className="misssteps">
        {PRINCIPLES.map(([t, d], i) => (
          <li key={t} className={'missstep-row' + (step === i + 1 ? ' now' : step > i ? ' lit' : '')}>
            <span className="missn">0{i + 1}</span>
            <div><b>{t}</b><p>{d}</p></div>
          </li>
        ))}
      </ol>
      <div className="missstage"><ShieldAssembly onStep={setStep} /></div>
    </div>

    <Reveal><h2 className="misssub">What is real, and what is a stand-in</h2>
      <p>We are deliberate about honesty. The clinic app, the attacks, and the exams are <b>real</b>. In the full stack the shield is <b>ModSecurity</b> and the AI is <b>Google Gemini</b>; on a laptop the shield is a regex stand-in and proposals come from reviewed templates. We never fake a result — a failed or unreachable test is never reported as a pass.</p>
      <p className="note">FixFort does not scan for holes it was not told about in production use; in the demo it runs a small built-in scanner against the bundled clinic only. It starts from a known finding and makes protection fast, proven, and temporary.</p>
    </Reveal>

    <Reveal><h3 id="terms" className="misssub sm">Terms</h3>
      <p className="note">Hackathon prototype, provided as-is for local educational use against the bundled clinic demo only. The clinic app is intentionally vulnerable — run it only on your own computer, never point it at systems you do not own.</p>
      <h3 id="privacy" className="misssub sm">Privacy</h3>
      <p className="note">The prototype keeps state only in your browser session. The AI step receives only the finding and a small sanitised snippet — never full codebases, keys, or customer data.</p>
    </Reveal>
  </div>
}
