import { BrowserRouter, Routes, Route } from 'react-router-dom';
import EmulatorPage from './pages/EmulatorPage';

/**
 * App Root Component
 *
 * Provides routing and layout structure for the AutoApp control interface.
 * Simplified layout without sidebar navigation.
 */

const App = () => {
  return (
    <BrowserRouter>
      <div
        style={{
          minHeight: '100vh',
          fontFamily: 'Inter, system-ui, sans-serif',
          backgroundColor: '#0f172a'
        }}
      >
        <Routes>
          <Route path="/" element={<EmulatorPage />} />
          <Route path="*" element={<EmulatorPage />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
};

export default App;
