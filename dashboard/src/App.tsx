function App() {
  return (
    <div style={{
      minHeight: '100vh',
      background: '#0A0A0A',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      flexDirection: 'column',
      gap: '16px',
      fontFamily: 'Geist, sans-serif',
    }}>
      <div style={{
        fontSize: '48px',
        fontWeight: 500,
        letterSpacing: '10px',
        color: '#E8E6E0',
      }}>
        WARDEN
      </div>
      <div style={{
        fontFamily: 'Geist Mono, monospace',
        fontSize: '12px',
        color: '#4A4AFF',
        letterSpacing: '0.1em',
      }}>
        SYSTEM INITIALIZING...
      </div>
    </div>
  )
}

export default App
