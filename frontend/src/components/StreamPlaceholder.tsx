const StreamPlaceholder = () => (
  <div className="video-placeholder">
    <div>
      <strong>Stream pending</strong>
      <p style={{ marginTop: '0.5rem' }}>
        Waiting for emulator to reach Running state.
      </p>
    </div>
  </div>
);

export default StreamPlaceholder;
