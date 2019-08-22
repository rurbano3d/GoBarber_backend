import jwt from 'jsonwebtoken';
import { promisify } from 'util';

import authConfig from '../../config/auth';

export default async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: 'Token not provided' });
  }

  // o authheader vem 'Bearer eyJhbGciOiJ', quando dou split ele separa em array bearer no indice 0 e eyJhbGciOiJ no indice 1
  // eu desestruturo e ficaria [bearer,token] porém você pode utiliza apenas [,token] pois não vamos utiliza o bearer

  const [, token] = authHeader.split(' ');
  try {
    const decoded = await promisify(jwt.verify)(token, authConfig.secret);

    req.userId = decoded.id;

    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Token invalid' });
  }
};
