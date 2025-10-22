import { Router } from 'express';
import { getEmulatorLogs, getStreamerLogs } from '../../services/logStreams';

const router = Router();

router.get('/:target', (req, res) => {
  const { target } = req.params;
  const limit = Number.parseInt(req.query.limit as string ?? '0', 10);
  const select = target === 'streamer' ? getStreamerLogs : getEmulatorLogs;
  const lines = select();
  const payload = limit > 0 ? lines.slice(-limit) : lines;

  res.json({
    target,
    lines: payload
  });
});

export const logsRouter = router;
