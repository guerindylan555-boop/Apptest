import { BrowserRouter, Routes, Route } from 'react-router-dom';
import EmulatorPage from './pages/EmulatorPage';
import DiscoveryPage from './pages/DiscoveryPage';

/**
 * App Root Component
 *
 * Provides routing and layout structure for the AutoApp control interface.
 */

const App = () => {
  return (
    <BrowserRouter>
      <div
        style={{
          minHeight: '100vh',
          fontFamily: 'Inter, system-ui, sans-serif'
        }}
      >
        <main style={{ width: '100%', overflowY: 'auto' }}>
          <Routes>
            <Route path="/" element={<EmulatorPage />} />
            <Route path="/discovery" element={<DiscoveryPage />} />
            <Route path="*" element={<EmulatorPage />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
};

export default App;
