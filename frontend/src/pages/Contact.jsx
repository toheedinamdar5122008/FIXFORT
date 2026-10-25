import React from 'react'
import { Link } from 'react-router-dom'
import { Reveal } from '../ui.jsx'
// Contact details are optional build-time settings (see .env.example). Nothing is invented: a channel is shown only if the team configured it.
const email = (import.meta.env.VITE_CONTACT_EMAIL || '').trim()
const url = (import.meta.env.VITE_CONTACT_URL || '').trim()
const safeUrl = /^https:\/\/[^\s]+$/i.test(url) ? url : ''
const safeEmail = /^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+$/.test(email) ? email : ''
const ROLES = [['Person A', 'AI and security engine', 'Rule proposals, attack tests, the exam runner and the Practice Room loop.'], ['Person B', 'Platform and data', 'Shields, API, database, event feed, verify-fix and retirement.'], ['Person C', 'Product and pitch', 'This website, the clinic portal, the legitimate-user tests, the certificate and the demo.']]
export default function Contact() {
  return <div className="wrap">
    <Reveal><span className="eyebrow">Contact</span><h1 className="pt">Talk to the FixFort team</h1>
      <p className="note">FixFort is a hackathon prototype built for Hackyard Build 2026 (IIT Guwahati, 24 to 25 October).</p></Reveal>
    <div className="cmpcode">
      <div className="card"><h3>How to reach us</h3>
        {safeEmail || safeUrl ? <ul className="clist">{safeEmail && <li>Email: <a href={'mailto:' + safeEmail}>{safeEmail}</a></li>}{safeUrl && <li>Project page: <a href={safeUrl} target="_blank" rel="noreferrer noopener">{safeUrl}</a></li>}</ul>
          : <p>No public contact channel has been configured for this prototype yet, and there is no message-sending service, so this page has no form that could pretend to send anything. At the event, ask the team directly.</p>}
        <p className="note">Team: set <span className="mono">VITE_CONTACT_EMAIL</span> and/or <span className="mono">VITE_CONTACT_URL</span> in <span className="mono">frontend/.env</span> and rebuild to publish a channel here.</p></div>
      <div className="card"><h3>What to ask us about</h3><ul className="clist"><li>How a temporary rule is proven safe before approval.</li><li>What is real in this demo and what is a stand-in (see the <Link to="/about">Mission</Link>).</li><li>How FixFort virtually patches a live CVE while the real fix is prepared.</li></ul></div></div>
    <p className="note">Security note: the clinic app is intentionally vulnerable and must only run on your own computer. See <Link to="/about#terms">Terms</Link>.</p>
  </div>
}
