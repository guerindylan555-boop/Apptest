import { BrowserRouter, Routes, Route } from 'react-router-dom';
import NavSidebar from './components/NavSidebar';
import EmulatorPage from './pages/EmulatorPage';
import AutomationWorkbenchPage from './pages/AutomationWorkbenchPage';

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
          display: 'flex',
          minHeight: '100vh',
          fontFamily: 'Inter, system-ui, sans-serif'
        }}
      >
        <NavSidebar />
        <main style={{ flex: 1, overflow: 'auto' }}>
          <Routes>
            <Route path="/" element={<EmulatorPage />} />
            <Route path="/automation" element={<AutomationWorkbenchPage />} />
            <Route path="*" element={<EmulatorPage />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
};

export default App;
