---
# the default layout is 'page'
icon: fas fa-info-circle
order: 5
---

<style>
.about-hero {
  border: 1px solid var(--card-border-color, rgba(134,140,151,0.18));
  border-radius: 0.9rem;
  padding: 1.25rem 1.35rem;
  background: var(--card-bg, var(--main-bg));
  margin-bottom: 2rem;
}
.about-name {
  font-size: 1.45rem;
  font-weight: 800;
  margin-bottom: 0.35rem;
  color: var(--heading-color, inherit);
}
.about-title {
  font-size: 0.92rem;
  color: var(--text-muted, #868c97);
  margin-bottom: 0.8rem;
}
.about-text {
  font-size: 0.95rem;
  line-height: 1.75;
  margin: 0;
}
.section-heading {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  font-size: 1.05rem;
  font-weight: 700;
  margin: 2rem 0 1.1rem 0;
}
.section-heading i { color: var(--link-color); font-size: 0.95rem; }
.section-heading::after {
  content: '';
  flex: 1;
  height: 1px;
  background: var(--card-border-color, rgba(134,140,151,0.2));
  margin-left: 0.5rem;
}
.cert-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 1rem;
}
.cert-card {
  border: 1px solid var(--card-border-color, rgba(134,140,151,0.18));
  border-radius: 0.65rem;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  background: var(--card-bg, var(--main-bg));
  transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
}
.cert-card:hover {
  transform: translateY(-3px);
  box-shadow: 0 8px 22px rgba(0,0,0,0.13);
  border-color: var(--link-color);
}
.cert-preview {
  display: block;
  position: relative;
  width: 100%;
  aspect-ratio: 600 / 464;
  overflow: hidden;
  text-decoration: none !important;
  background: rgba(134,140,151,0.07);
}
.cert-preview-img {
  position: absolute;
  inset: 0;
  background-size: cover;
  background-position: top center;
  background-repeat: no-repeat;
  transition: transform 0.3s ease;
}
.cert-card:hover .cert-preview-img { transform: scale(1.04); }
.cert-overlay {
  position: absolute;
  inset: 0;
  background: rgba(0,0,0,0.4);
  display: flex;
  align-items: center;
  justify-content: center;
  opacity: 0;
  transition: opacity 0.2s;
}
.cert-card:hover .cert-overlay { opacity: 1; }
.cert-overlay span {
  font-size: 0.78rem;
  font-weight: 600;
  color: #fff;
  background: rgba(0,0,0,0.55);
  border: 1px solid rgba(255,255,255,0.3);
  padding: 0.35rem 0.85rem;
  border-radius: 2rem;
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  backdrop-filter: blur(4px);
}
.cert-footer {
  padding: 0.65rem 0.85rem;
  border-top: 1px solid var(--card-border-color, rgba(134,140,151,0.15));
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 0.5rem;
}
.cert-name {
  font-size: 0.88rem;
  font-weight: 700;
  color: var(--heading-color, inherit);
  text-decoration: none;
  line-height: 1.2;
  display: block;
}
.cert-name:hover { text-decoration: underline; color: var(--link-color); }
.cert-issuer {
  font-size: 0.68rem;
  color: var(--text-muted, #868c97);
  margin-top: 0.1rem;
}
@media (max-width: 480px) {
  .cert-grid { grid-template-columns: 1fr; }
  .about-hero { padding: 1rem; }
}
</style>

<div class="about-hero">
  <div class="about-name">Abdullhafeeth Marabit</div>
  <div class="about-title">aka 0x3xP01t3r</div>
  <p class="about-text">
    I am a cybersecurity graduate focused on DFIR, web application security, and penetration testing.
    I hold multiple offensive-security certifications, including CRTP, eCPPT, eWPTX, CRTA, and KWAPTA.
    My goal is to keep building practical security tools, sharing knowledge, and contributing to the cybersecurity community through research, CTFs, and hands-on projects.
  </p>
</div>

<div class="section-heading"><i class="fas fa-certificate"></i> Certifications</div>

<div class="cert-grid">

<div class="cert-card">
  <a class="cert-preview" href="https://www.credential.net/8b866ba9-8b2f-40e6-81d3-b11b3c7bf00c#acc.i7eSX2Fu" target="_blank" rel="noopener" aria-label="View CRTP certificate">
    <div class="cert-preview-img" style="background-image: url('/assets/img/certs/CRTP.jpg')"></div>
    <div class="cert-overlay"><span><i class="fas fa-external-link-alt"></i> View Certificate</span></div>
  </a>
  <div class="cert-footer"><div><a class="cert-name" href="https://www.credential.net/8b866ba9-8b2f-40e6-81d3-b11b3c7bf00c#acc.i7eSX2Fu" target="_blank" rel="noopener">CRTP</a><div class="cert-issuer">Altered Security</div></div></div>
</div>

<div class="cert-card">
  <a class="cert-preview" href="https://certs.ine.com/494ad202-4cc7-48cc-958b-22c815ab43d2#acc.2q0TumXL" target="_blank" rel="noopener" aria-label="View eCPPT certificate">
    <div class="cert-preview-img" style="background-image: url('/assets/img/certs/eCPPT.jpg')"></div>
    <div class="cert-overlay"><span><i class="fas fa-external-link-alt"></i> View Certificate</span></div>
  </a>
  <div class="cert-footer"><div><a class="cert-name" href="https://certs.ine.com/494ad202-4cc7-48cc-958b-22c815ab43d2#acc.2q0TumXL" target="_blank" rel="noopener">eCPPT</a><div class="cert-issuer">INE Security</div></div></div>
</div>

<div class="cert-card">
  <a class="cert-preview" href="https://certs.ine.com/a96b62f9-2747-4162-911c-4cd397d1a637#acc.vrNhZYIJ" target="_blank" rel="noopener" aria-label="View eWPTX certificate">
    <div class="cert-preview-img" style="background-image: url('/assets/img/certs/eWPTX.jpg')"></div>
    <div class="cert-overlay"><span><i class="fas fa-external-link-alt"></i> View Certificate</span></div>
  </a>
  <div class="cert-footer"><div><a class="cert-name" href="https://certs.ine.com/a96b62f9-2747-4162-911c-4cd397d1a637#acc.vrNhZYIJ" target="_blank" rel="noopener">eWPTX</a><div class="cert-issuer">INE Security</div></div></div>
</div>
<div class="cert-card">
  <a class="cert-preview" href="https://labs.cyberwarfare.live/credential/achievement/6887ea98f4c7625a294aa2a0" target="_blank" rel="noopener" aria-label="View CRTA certificate">
    <div class="cert-preview-img" style="background-image: url('/assets/img/certs/CRTA.jpg')"></div>
    <div class="cert-overlay"><span><i class="fas fa-external-link-alt"></i> View Certificate</span></div>
  </a>
  <div class="cert-footer"><div><a class="cert-name" href="https://labs.cyberwarfare.live/credential/achievement/6887ea98f4c7625a294aa2a0" target="_blank" rel="noopener">CRTA</a><div class="cert-issuer">Cyberwarfare Labs</div></div></div>
</div>


</div>
