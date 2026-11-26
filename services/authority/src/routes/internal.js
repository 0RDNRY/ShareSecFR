import { Router } from 'express';
import { UserAttr } from '../models/index.js';

const router = Router();

// GET /internal/users/:id/attributes
// Called by the API's policy gate to get live attributes
router.get('/users/:id/attributes', async (req, res, next) => {
  try {
    const rec = await UserAttr.findOne({ userId: req.params.id }).lean();
    res.json({ attributes: rec?.attributes ?? [] });
  } catch (err) {
    next(err);
  }
});

export default router;
