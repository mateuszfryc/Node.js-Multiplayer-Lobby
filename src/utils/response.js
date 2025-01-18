export function jsonRes(res, msg, error, data, status = 200) {
  return res.status(status).json({ message: msg, error, data });
}
