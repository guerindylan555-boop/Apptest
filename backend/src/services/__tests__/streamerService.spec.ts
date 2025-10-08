import { sessionStore } from '../../state/sessionStore';
import { issueStreamTicket } from '../streamerService';
import type { EmulatorSession } from '../../types/session';

// Mock the sessionStore
jest.mock('../../state/sessionStore');

// Mock the emulatorLifecycle
jest.mock('../emulatorLifecycle', () => ({
  findRunningEmulator: jest.fn().mockResolvedValue(null),
  getEmulatorSerial: jest.fn().mockResolvedValue('emulator-5554'),
  // Add other exported functions if needed by the streamerService
  __esModule: true
}));

// Mock the streamerService's ensureStreamer function
jest.mock('../streamerService', () => {
  const originalModule = jest.requireActual('../streamerService');
  return {
    ...originalModule,
    ensureStreamer: jest.fn().mockResolvedValue(undefined)
  };
});

const mockSessionStore = sessionStore as jest.Mocked<typeof sessionStore>;

describe('streamerService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('issueStreamTicket', () => {
    it('should issue ticket when session state is Running', async () => {
      const mockSession: EmulatorSession = { state: 'Running', avdName: 'test-avd' };
      const streamUrl = 'http://127.0.0.1:8000/?action=stream&udid=emulator-5554&player=mse';
      const mockTicket = {
        token: 'test-token' as `${string}-${string}-${string}-${string}-${string}`,
        expiresAt: Date.now() + 60000,
        emulatorSerial: 'emulator-5554',
        bridgeUrl: streamUrl
      };

      mockSessionStore.getSession.mockReturnValue(mockSession);
      mockSessionStore.generateStreamTicket.mockReturnValue(mockTicket);

      const result = await issueStreamTicket();

      expect(mockSessionStore.getSession).toHaveBeenCalled();
      expect(mockSessionStore.generateStreamTicket).toHaveBeenCalledWith('emulator-5554', streamUrl);
      expect(result).toEqual({
        token: 'test-token',
        url: streamUrl,
        expiresAt: expect.any(String)
      });
    });

    it('should throw error when session state is not Running', async () => {
      const mockSession: EmulatorSession = { state: 'Stopped', avdName: 'test-avd' };
      mockSessionStore.getSession.mockReturnValue(mockSession);

      await expect(issueStreamTicket()).rejects.toThrow('Stream tickets available only in Running state');
      expect(mockSessionStore.generateStreamTicket).not.toHaveBeenCalled();
    });

    it('should throw error when session state is Error', async () => {
      const mockSession: EmulatorSession = { state: 'Error', avdName: 'test-avd' };
      mockSessionStore.getSession.mockReturnValue(mockSession);

      await expect(issueStreamTicket()).rejects.toThrow('Stream tickets available only in Running state');
      expect(mockSessionStore.generateStreamTicket).not.toHaveBeenCalled();
    });
  });
});
