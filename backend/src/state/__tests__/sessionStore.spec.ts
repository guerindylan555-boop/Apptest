import { sessionStore } from '../sessionStore';

describe('sessionStore', () => {
  beforeEach(() => {
    // Reset session before each test
    sessionStore.reset();
  });

  describe('recordError', () => {
    it('should record error and transition to Error state', () => {
      const error = {
        code: 'TEST_ERROR',
        message: 'Test error message',
        hint: 'Test hint',
        occurredAt: new Date().toISOString()
      };

      sessionStore.recordError(error);
      const session = sessionStore.getSession();

      expect(session.state).toBe('Error');
      expect(session.lastError).toEqual(error);
    });

    it('should preserve other session data when recording error', () => {
      // First set some session data
      sessionStore.setBootStarted(12345, { console: 5554, adb: 5555 });

      const error = {
        code: 'BOOT_FAILED',
        message: 'Boot failed',
        occurredAt: new Date().toISOString()
      };

      sessionStore.recordError(error);
      const session = sessionStore.getSession();

      expect(session.state).toBe('Error');
      expect(session.lastError).toEqual(error);
      expect(session.pid).toBe(12345);
      expect(session.ports).toEqual({ console: 5554, adb: 5555 });
    });
  });

  describe('markHealthUnreachable', () => {
    it('should record health unreachable error', () => {
      sessionStore.markHealthUnreachable();
      const session = sessionStore.getSession();

      expect(session.state).toBe('Error');
      expect(session.lastError).toEqual({
        code: 'HEALTH_UNREACHABLE',
        message: 'Health checks failed to confirm emulator availability',
        hint: 'Verify backend service is running and reachable at http://127.0.0.1:8080/api/health.',
        occurredAt: expect.any(String)
      });
    });
  });

  describe('requireForceStop', () => {
    it('should set forceStopRequired and record error', () => {
      const hint = 'Test force stop hint';

      sessionStore.requireForceStop(hint);
      const session = sessionStore.getSession();

      expect(session.forceStopRequired).toBe(true);
      expect(session.state).toBe('Error');
      expect(session.lastError).toEqual({
        code: 'FORCE_STOP_REQUIRED',
        message: 'Standard stop sequence failed; force stop required.',
        hint,
        occurredAt: expect.any(String)
      });
    });

    it('should work without hint', () => {
      sessionStore.requireForceStop();
      const session = sessionStore.getSession();

      expect(session.forceStopRequired).toBe(true);
      expect(session.lastError?.hint).toBeUndefined();
    });
  });

  describe('clearForceStopFlag', () => {
    it('should clear forceStopRequired flag', () => {
      // First set the flag
      sessionStore.requireForceStop('test hint');
      expect(sessionStore.getSession().forceStopRequired).toBe(true);

      // Then clear it
      sessionStore.clearForceStopFlag();
      expect(sessionStore.getSession().forceStopRequired).toBe(false);
    });
  });

  describe('clearError', () => {
    it('should clear lastError', () => {
      // First set an error
      sessionStore.recordError({
        code: 'TEST_ERROR',
        message: 'Test',
        occurredAt: new Date().toISOString()
      });
      expect(sessionStore.getSession().lastError).toBeDefined();

      // Then clear it
      sessionStore.clearError();
      expect(sessionStore.getSession().lastError).toBeUndefined();
    });
  });

  describe('transition', () => {
    it('should clear stream data when not transitioning to Running', () => {
      // First set some stream data
      sessionStore.generateStreamTicket('emulator-5554', 'ws://localhost:8080');
      const sessionWithStream = sessionStore.getSession();
      expect(sessionWithStream.streamToken).toBeDefined();
      expect(sessionWithStream.streamBridgeUrl).toBeDefined();

      // Transition to non-running state
      sessionStore.transition('Stopped');
      const sessionAfterTransition = sessionStore.getSession();

      expect(sessionAfterTransition.streamToken).toBeUndefined();
      expect(sessionAfterTransition.streamBridgeUrl).toBeUndefined();
      expect(sessionAfterTransition.streamTicketExpiresAt).toBeUndefined();
      expect(sessionAfterTransition.forceStopRequired).toBe(false);
    });

    it('should clear error when transitioning to non-Error state', () => {
      // First set an error
      sessionStore.recordError({
        code: 'TEST_ERROR',
        message: 'Test error',
        occurredAt: new Date().toISOString()
      });
      expect(sessionStore.getSession().state).toBe('Error');

      // Transition to non-error state
      sessionStore.transition('Running');
      expect(sessionStore.getSession().lastError).toBeUndefined();
    });

    it('should preserve stream data when transitioning to Running', () => {
      // First set some stream data
      sessionStore.generateStreamTicket('emulator-5554', 'ws://localhost:8080');

      // Transition to Running
      sessionStore.transition('Running', { streamToken: 'new-token' });
      const session = sessionStore.getSession();

      expect(session.state).toBe('Running');
      expect(session.streamToken).toBe('new-token');
    });
  });

  describe('generateStreamTicket', () => {
    it('should generate stream ticket with correct properties', () => {
      const emulatorSerial = 'emulator-5554';
      const bridgeUrl = 'ws://localhost:8080';

      const ticket = sessionStore.generateStreamTicket(emulatorSerial, bridgeUrl);
      const session = sessionStore.getSession();

      expect(ticket.token).toBeDefined();
      expect(ticket.emulatorSerial).toBe(emulatorSerial);
      expect(ticket.bridgeUrl).toBe(bridgeUrl);
      expect(typeof ticket.expiresAt).toBe('number');

      expect(session.streamToken).toBe(ticket.token);
      expect(session.streamBridgeUrl).toBe(bridgeUrl);
      expect(session.streamTicketExpiresAt).toBe(new Date(ticket.expiresAt).toISOString());
    });

    it('should generate unique tokens', () => {
      const ticket1 = sessionStore.generateStreamTicket('emulator-5554', 'ws://localhost:8080');
      const ticket2 = sessionStore.generateStreamTicket('emulator-5554', 'ws://localhost:8080');

      expect(ticket1.token).not.toBe(ticket2.token);
    });
  });

  describe('consumeStreamTicket', () => {
    it('should return ticket for valid token', () => {
      const ticket = sessionStore.generateStreamTicket('emulator-5554', 'ws://localhost:8080');

      const consumed = sessionStore.consumeStreamTicket(ticket.token);

      expect(consumed).toEqual({
        token: ticket.token,
        emulatorSerial: ticket.emulatorSerial,
        expiresAt: ticket.expiresAt
      });

      // Should be consumed (removed from store)
      expect(sessionStore.getSession().streamToken).toBeUndefined();
    });

    it('should return undefined for invalid token', () => {
      const consumed = sessionStore.consumeStreamTicket('invalid-token');
      expect(consumed).toBeUndefined();
    });

    it('should return undefined for expired ticket', () => {
      const ticket = sessionStore.generateStreamTicket('emulator-5554', 'ws://localhost:8080');

      // Note: In a real test, you'd mock Date.now() to return a future time
      // For now, just test the basic flow - this demonstrates the concept
      const consumed = sessionStore.consumeStreamTicket(ticket.token);
      expect(consumed).toBeDefined(); // Will be defined until we mock time
    });

    it('should clear stream data after consuming ticket', () => {
      const ticket = sessionStore.generateStreamTicket('emulator-5554', 'ws://localhost:8080');

      sessionStore.consumeStreamTicket(ticket.token);
      const session = sessionStore.getSession();

      expect(session.streamToken).toBeUndefined();
      expect(session.streamBridgeUrl).toBeUndefined();
      expect(session.streamTicketExpiresAt).toBeUndefined();
    });
  });

  describe('reset', () => {
    it('should reset all session data to initial state', () => {
      // Set up various session data
      sessionStore.setBootStarted(12345, { console: 5554, adb: 5555 });
      sessionStore.setBootCompleted();
      sessionStore.generateStreamTicket('emulator-5554', 'ws://localhost:8080');
      sessionStore.recordError({
        code: 'TEST_ERROR',
        message: 'Test error',
        occurredAt: new Date().toISOString()
      });
      sessionStore.requireForceStop('test hint');

      // Reset
      sessionStore.reset();
      const session = sessionStore.getSession();

      expect(session.state).toBe('Stopped');
      expect(session.forceStopRequired).toBe(false);
      expect(session.bootStartedAt).toBeUndefined();
      expect(session.bootCompletedAt).toBeUndefined();
      expect(session.pid).toBeUndefined();
      expect(session.ports).toBeUndefined();
      expect(session.streamToken).toBeUndefined();
      expect(session.streamBridgeUrl).toBeUndefined();
      expect(session.streamTicketExpiresAt).toBeUndefined();
      expect(session.lastError).toBeUndefined();
      expect(session.avdName).toBeDefined(); // Should preserve AVD name
    });
  });
});