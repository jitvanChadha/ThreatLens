import logoImg from '../assets/logo.png';

export default function PageHeader() {
  return (
    <header className="page-header" id="page-header">
      <div className="header-logo-img">
        <img src={logoImg} alt="ThreatLens" draggable="false" />
      </div>
    </header>
  );
}
