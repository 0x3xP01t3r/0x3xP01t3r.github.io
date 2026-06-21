---
# the default layout is 'page'
icon: fas fa-info-circle
order: 5
---

<style>
.profile-wrap {
  display: grid;
  grid-template-columns: 1.2fr 0.8fr;
  gap: 1rem;
  margin-bottom: 2rem;
}

.profile-card,
.focus-card,
.cert-card {
  border: 1px solid var(--card-border-color, rgba(134,140,151,0.18));
  background:
    linear-gradient(135deg, rgba(88,166,255,0.08), transparent 35%),
    var(--card-bg, var(--main-bg));
  border-radius: 1rem;
}

.profile-card {
  padding: 1.45rem;
  position: relative;
  overflow: hidden;
}

.profile-card::before {
  content: "";
  position: absolute;
  width: 160px;
  height: 160px;
  right: -55px;
  top: -55px;
  border-radius: 50%;
  background: rgba(88,166,255,0.12);
  filter: blur(2px);
}

.profile-kicker {
  font-size: 0.72rem;
  font-weight: 800;
  letter-spacing: 0.11em;
  text-transform: uppercase;
  color: var(--link-color);
  margin-bottom: 0.55rem;
}

.profile-name {
  font-size: 1.7rem;
  font-weight: 900;
  line-height: 1.15;
  color: var(--heading-color, inherit);
  margin-bottom: 0.35rem;
}

.profile-alias {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  font-size: 0.82rem;
  font-weight: 700;
  color: var(--text-muted, #868c97);
  border: 1px solid var(--card-border-color, rgba(134,140,151,0.18));
  border-radius: 999px;
  padding: 0.28rem 0.65rem;
  margin-bottom: 1rem;
}

.profile-text {
  font-size: 0.96rem;
  line-height: 1.75;
  margin: 0;
  max-width: 58rem;
}

.focus-card {
  padding: 1.1rem;
  display: grid;
  align-content: center;
  gap: 0.75rem;
}

.focus-item {
  display: flex;
  align-items: center;
  gap: 0.65rem;
  padding: 0.7rem 0.75rem;
  border-radius: 0.75rem;
  background: rgba(134,140,151,0.07);
}

.focus-item i {
  color: var(--link-color);
  width: 1rem;
  text-align: center;
}

.focus-item span {
  font-size: 0.85rem;
  font-weight: 700;
}

.section-heading {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  font-size: 1.05rem;
  font-weight: 800;
  margin: 2rem 0 1.1rem 0;
}

.section-heading i {
  color: var(--link-color);
  font-size: 0.95rem;
}

.section-heading::after {
  content: "";
  flex: 1;
  height: 1px;
  background: var(--card-border-color, rgba(134,140,151,0.2));
  margin-left: 0.5rem;
}

.cert-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(230px, 1fr));
  gap: 1rem;
}

.cert-card {
  overflow: hidden;
  transition: transform 0.22s ease, box-shadow 0.22s ease, border-color 0.22s ease;
}

.cert-card:hover {
  transform: translateY(-4px);
  box-shadow: 0 12px 28px rgba(0,0,0,0.14);
  border-color: var(--link-color);
}

.cert-preview {
  display: block;
  position: relative;
  aspect-ratio: 600 / 430;
  overflow: hidden;
  background: rgba(134,140,151,0.07);
  text-decoration: none !important;
}

.cert-preview-img {
  position: absolute;
  inset: 0;
  background-size: cover;
  background-position: top center;
  background-repeat: no-repeat;
  transition: transform 0.35s ease, filter 0.35s ease;
}

.cert-card:hover .cert-preview-img {
  transform: scale(1.045);
  filter: brightness(0.78);
}

.cert-badge {
  position: absolute;
  left: 0.75rem;
  top: 0.75rem;
  z-index: 2;
  font-size: 0.68rem;
  font-weight: 800;
  color: #fff;
  background: rgba(0,0,0,0.58);
  border: 1px solid rgba(255,255,255,0.22);
  border-radius: 999px;
  padding: 0.25rem 0.55rem;
  backdrop-filter: blur(5px);
}

.cert-overlay {
  position: absolute;
  inset: 0;
  background: linear-gradient(to top, rgba(0,0,0,0.66), rgba(0,0,0,0.08));
  display: flex;
  align-items: flex-end;
  justify-content: center;
  padding: 1rem;
  opacity: 0;
  transition: opacity 0.22s ease;
}

.cert-card:hover .cert-overlay {
  opacity: 1;
}

.cert-overlay span {
  font-size: 0.78rem;
  font-weight: 800;
  color: #fff;
  background: rgba(0,0,0,0.55);
  border: 1px solid rgba(255,255,255,0.25);
  padding: 0.38rem 0.85rem;
  border-radius: 999px;
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
}

.cert-body {
  padding: 0.85rem 0.9rem 0.95rem 0.9rem;
}

.cert-name {
  font-size: 0.95rem;
  font-weight: 850;
  color: var(--heading-color, inherit);
  text-decoration: none;
  line-height: 1.2;
  display: inline-block;
}

.cert-name:hover {
  color: var(--link-color);
  text-decoration: underline;
}

.cert-issuer {
  font-size: 0.72rem;
  color: var(--text-muted, #868c97);
  margin-top: 0.18rem;
}

.cert-desc {
  font-size: 0.75rem;
  line-height: 1.55;
  color: var(--text-muted, #868c97);
  margin-top: 0.55rem;
}

@media (max-width: 760px) {
  .profile-wrap {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 480px) {
  .cert-grid {
    grid-template-columns: 1fr;
  }

  .profile-card,
  .focus-card {
    padding: 1rem;
  }

  .profile-name {
    font-size: 1.45rem;
  }
}

@media (prefers-reduced-motion: reduce) {
  .cert-card,
  .cert-preview-img,
  .cert-overlay {
    transition: none;
  }

  .cert-card:hover {
    transform: none;
  }
}
</style>

<div class="profile-wrap">
  <div class="profile-card">
    <div class="profile-kicker">Cybersecurity Portfolio</div>
    <div class="profile-name">Abdullhafeeth Marabit</div>
    <div class="profile-alias"><i class="fas fa-terminal"></i> aka 0x3xP01t3r</div>
    <p class="profile-text">
      I am a cybersecurity graduate focused on DFIR, web application security, and penetration testing.
      I hold multiple offensive-security certifications, including CRTP, eCPPT, eWPTX, CRTA, and KWAPTA.
      My goal is sharing knowledge, and contributing to the cybersecurity community through research, CTFs, and hands-on projects.
    </p>
  </div>

  <div class="focus-card">
    <div class="focus-item"><i class="fas fa-microscope"></i><span>DFIR </span></div>
    <div class="focus-item"><i class="fas fa-bug"></i><span>Web Application Security</span></div>
    <div class="focus-item"><i class="fas fa-flag"></i><span>CTFs & Challenge Building</span></div>
    <div class="focus-item"><i class="fas fa-tools"></i><span>Security Tool Development</span></div>
  </div>
</div>

<div class="section-heading"><i class="fas fa-certificate"></i> Certifications</div>

<div class="cert-grid">

<div class="cert-card">
  <a class="cert-preview" href="https://www.credential.net/8b866ba9-8b2f-40e6-81d3-b11b3c7bf00c#acc.i7eSX2Fu" target="_blank" rel="noopener" aria-label="View CRTP certificate">
    <div class="cert-badge">Altered Security</div>
    <div class="cert-preview-img" style="background-image: url('/assets/img/certs/CRTP.jpg')"></div>
    <div class="cert-overlay"><span><i class="fas fa-external-link-alt"></i> View Certificate</span></div>
  </a>
  <div class="cert-body">
    <a class="cert-name" href="https://www.credential.net/8b866ba9-8b2f-40e6-81d3-b11b3c7bf00c#acc.i7eSX2Fu" target="_blank" rel="noopener">CRTP</a>
    <div class="cert-issuer">Certified Red Team Professional</div>
    <div class="cert-desc">Active Directory security, enumeration, privilege escalation, and red team methodology.</div>
  </div>
</div>

<div class="cert-card">
  <a class="cert-preview" href="https://certs.ine.com/494ad202-4cc7-48cc-958b-22c815ab43d2#acc.2q0TumXL" target="_blank" rel="noopener" aria-label="View eCPPT certificate">
    <div class="cert-badge">INE Security</div>
    <div class="cert-preview-img" style="background-image: url('/assets/img/certs/eCPPT.jpg')"></div>
    <div class="cert-overlay"><span><i class="fas fa-external-link-alt"></i> View Certificate</span></div>
  </a>
  <div class="cert-body">
    <a class="cert-name" href="https://certs.ine.com/494ad202-4cc7-48cc-958b-22c815ab43d2#acc.2q0TumXL" target="_blank" rel="noopener">eCPPT</a>
    <div class="cert-issuer">Certified Professional Penetration Tester</div>
    <div class="cert-desc">Hands-on penetration testing covering exploitation, post-exploitation, web, and Active Directory.</div>
  </div>
</div>

<div class="cert-card">
  <a class="cert-preview" href="https://certs.ine.com/a96b62f9-2747-4162-911c-4cd397d1a637#acc.vrNhZYIJ" target="_blank" rel="noopener" aria-label="View eWPTX certificate">
    <div class="cert-badge">INE Security</div>
    <div class="cert-preview-img" style="background-image: url('/assets/img/certs/eWPTX.jpg')"></div>
    <div class="cert-overlay"><span><i class="fas fa-external-link-alt"></i> View Certificate</span></div>
  </a>
  <div class="cert-body">
    <a class="cert-name" href="https://certs.ine.com/a96b62f9-2747-4162-911c-4cd397d1a637#acc.vrNhZYIJ" target="_blank" rel="noopener">eWPTX</a>
    <div class="cert-issuer">Web Application Penetration Tester eXtreme</div>
    <div class="cert-desc">Advanced web application testing, API security, authentication attacks, and WAF bypass.</div>
  </div>
</div>

<div class="cert-card">
  <a class="cert-preview" href="https://labs.cyberwarfare.live/credential/achievement/6887ea98f4c7625a294aa2a0" target="_blank" rel="noopener" aria-label="View CRTA certificate">
    <div class="cert-badge">Cyberwarfare Labs</div>
    <div class="cert-preview-img" style="background-image: url('/assets/img/certs/CRTA.jpg')"></div>
    <div class="cert-overlay"><span><i class="fas fa-external-link-alt"></i> View Certificate</span></div>
  </a>
  <div class="cert-body">
    <a class="cert-name" href="https://labs.cyberwarfare.live/credential/achievement/6887ea98f4c7625a294aa2a0" target="_blank" rel="noopener">CRTA</a>
    <div class="cert-issuer">Certified Red Team Analyst</div>
    <div class="cert-desc">Red team fundamentals, pivoting, internal operations, and enterprise attack paths.</div>
  </div>
</div>

</div>
