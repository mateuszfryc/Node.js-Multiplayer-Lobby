export function jsonRes(res, error, data, status = 200) {
  return res.status(status).json({ error, data });
}
