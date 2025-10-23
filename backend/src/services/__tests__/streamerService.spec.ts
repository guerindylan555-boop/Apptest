const mockSessionStore = {
  getSession: jest.fn(),
  generateStreamTicket: jest.fn()
};

jest.mock('../../state/sessionStore', () => ({
  sessionStore: mockSessionStore
}));

import type { EmulatorSession } from '../../types/session';

const loadStreamerService = async () => {
  jest.resetModules();
  return import('../streamerService');
};

describe('streamerService', () => {
  beforeEach(() => {
    jest.resetAllMocks();
    delete process.env.EMULATOR_WEBRTC_PUBLIC_URL;
  });

  it('returns stream configuration when session is running', async () => {
    const mockSession: EmulatorSession = { state: 'Running', avdName: 'test-avd' };
    const mockTicket = {
      token: 'mock-token',
      emulatorSerial: 'external-emulator',
      expiresAt: Date.now() + 60_000
    };

    mockSessionStore.getSession.mockReturnValue(mockSession);
    mockSessionStore.generateStreamTicket.mockReturnValue(mockTicket);

    const { issueStreamTicket } = await loadStreamerService();
    const result = await issueStreamTicket({ requestHost: 'example.com:443', protocol: 'https' });

    expect(mockSessionStore.getSession).toHaveBeenCalledTimes(1);
    expect(mockSessionStore.generateStreamTicket).toHaveBeenCalledWith('external-emulator');
    expect(result.token).toBe(mockTicket.token);
    expect(result.url).toBe('https://example.com/');
    expect(result.grpcUrl).toBe(result.url);
    expect(result.expiresAt).toEqual(new Date(mockTicket.expiresAt).toISOString());
    expect(result.iceServers).toEqual([]);
  });

  it('honours configured public url when provided', async () => {
    process.env.EMULATOR_WEBRTC_PUBLIC_URL = 'http://public-host:9000/webrtc';
    const mockSession: EmulatorSession = { state: 'Running', avdName: 'test-avd' };
    const mockTicket = {
      token: 'mock-token',
      emulatorSerial: 'external-emulator',
      expiresAt: Date.now() + 60_000
    };

    mockSessionStore.getSession.mockReturnValue(mockSession);
    mockSessionStore.generateStreamTicket.mockReturnValue(mockTicket);

    const { issueStreamTicket } = await loadStreamerService();
    const result = await issueStreamTicket();

    expect(result.url).toBe('http://public-host:9000/webrtc/');
  });

  it('throws when session is not running', async () => {
    const mockSession: EmulatorSession = { state: 'Stopped', avdName: 'test-avd' };
    mockSessionStore.getSession.mockReturnValue(mockSession);

    const { issueStreamTicket } = await loadStreamerService();

    await expect(issueStreamTicket()).rejects.toThrow(
      'Stream configuration is available only when the emulator is running'
    );
    expect(mockSessionStore.generateStreamTicket).not.toHaveBeenCalled();
  });
});
