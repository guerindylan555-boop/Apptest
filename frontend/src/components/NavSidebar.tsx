import { Link, useLocation } from 'react-router-dom';

/**
 * Navigation Sidebar
 *
 * Provides primary navigation between Emulator and Apps sections.
 */

const NavSidebar = () => {
  const location = useLocation();

  const navItems = [
    { path: '/', label: 'Emulator', icon: '📱' },
    { path: '/automation', label: 'Automation', icon: '🤖' }
  ];

  const isActive = (path: string) => {
    if (path === '/') {
      return location.pathname === '/';
    }
    return location.pathname.startsWith(path);
  };

  return (
    <nav
      style={{
        width: '200px',
        backgroundColor: '#f8f9fa',
        borderRight: '1px solid #e0e0e0',
        padding: '1rem 0',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.5rem'
      }}
    >
      <div style={{ padding: '0 1rem', marginBottom: '1rem' }}>
        <h2 style={{ margin: 0, fontSize: '1.25rem' }}>AutoApp</h2>
        <p style={{ margin: 0, fontSize: '0.75rem', color: '#666' }}>Test Control Hub</p>
      </div>

      {navItems.map((item) => {
        const active = isActive(item.path);
        return (
          <Link
            key={item.path}
            to={item.path}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.75rem',
              padding: '0.75rem 1rem',
              textDecoration: 'none',
              color: active ? '#000' : '#666',
              backgroundColor: active ? '#e3f2fd' : 'transparent',
              borderLeft: active ? '3px solid #2196f3' : '3px solid transparent',
              transition: 'all 0.2s ease'
            }}
          >
            <span style={{ fontSize: '1.25rem' }}>{item.icon}</span>
            <span style={{ fontWeight: active ? 600 : 400 }}>{item.label}</span>
          </Link>
        );
      })}
    </nav>
  );
};

export default NavSidebar;
