import React, { useEffect, useState } from 'react'
import { Routes, Route, NavLink, Link, useLocation } from 'react-router-dom'
import Home from './pages/Home.jsx'
import Command from './pages/Command.jsx'
import Pipeline from './pages/Pipeline.jsx'
import Feed from './pages/Feed.jsx'
import Lifecycle from './pages/Lifecycle.jsx'
import About from './pages/About.jsx'
import Clinic from './pages/Clinic.jsx'
import Contact from './pages/Contact.jsx'
import { Logo, ConnBar } from './ui.jsx'
import { useFF } from './store.jsx'
const tabs = [['/dashboard','Command Center'],['/pipeline','Pipeline'],['/feed','Live Feed'],['/lifecycle','Lifecycle'],['/clinic','Clinic Demo']]
const NotFound = () => <div className="wrap nf"><h1 className="pt">Page not found</h1><p className="note">That route does not exist.</p><Link className="btn" to="/">Back to home</Link></div>
export default function App() {
  const loc = useLocation(); const home = loc.pathname === '/'; const ff = useFF(); const { toast } = ff
  const [open, setOpen] = useState(false)
  useEffect(() => { setOpen(false); if (loc.hash) { document.getElementById(loc.hash.slice(1))?.scrollIntoView() } else window.scrollTo(0, 0) }, [loc.pathname, loc.hash])
  useEffect(() => { const k = (e) => e.key === 'Escape' && setOpen(false); addEventListener('keydown', k); return () => removeEventListener('keydown', k) }, [])
  const prod = !home && loc.pathname !== '/about' && tabs.some(t => t[0] === loc.pathname)
  return <>
    <a className="skip" href="#main">Skip to content</a>
    <header className={'top ' + (home ? 'over' : '')}><Logo/>
      <nav aria-label="Main"><NavLink to="/" end>Home</NavLink><NavLink to="/dashboard">Dashboard</NavLink><NavLink to="/about">Mission</NavLink></nav>
      <Link className="btn ghost" to="/dashboard">Get Started</Link>
      <button className="burger" aria-expanded={open} aria-controls="drawer" aria-label="Menu" onClick={() => setOpen(o => !o)}>{open ? '✕' : '☰'}</button></header>
    {open && <nav id="drawer" className="drawer" aria-label="Mobile"><NavLink to="/" end>Home</NavLink>{tabs.map(([p,l]) => <NavLink key={p} to={p}>{l}</NavLink>)}<NavLink to="/about">Mission</NavLink></nav>}
    {prod && <nav className="sub" aria-label="Product">{tabs.map(([p,l]) => <NavLink key={p} to={p}>{l}</NavLink>)}</nav>}
    {prod && <ConnBar f={ff}/>}
    <main id="main" key={loc.pathname} className="page"><Routes>
      <Route path="/" element={<Home/>}/><Route path="/dashboard" element={<Command/>}/><Route path="/pipeline" element={<Pipeline/>}/>
      <Route path="/feed" element={<Feed/>}/><Route path="/lifecycle" element={<Lifecycle/>}/><Route path="/about" element={<About/>}/><Route path="/clinic" element={<Clinic/>}/><Route path="/contact" element={<Contact/>}/><Route path="*" element={<NotFound/>}/>
    </Routes></main>
    <footer className="foot"><span>FixFort hackathon prototype. Simulated or stand-in data is always labelled.</span><Link to="/contact">Contact</Link><Link to="/about#terms">Terms</Link><Link to="/about#privacy">Privacy</Link></footer>
    {toast && <div key={toast.id} className={'toast ' + toast.kind} role="status">{toast.msg}</div>}
  </>
}
