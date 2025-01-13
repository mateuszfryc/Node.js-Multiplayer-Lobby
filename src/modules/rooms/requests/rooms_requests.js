import { rooms_state } from '#rooms/state/rooms_state.js';

export const getRooms = async (req, res) => {
  const prfx = 'Get Rooms:';

  res.status(200).json(rooms_state);
  console.log(`${prfx} Returned list of ${rooms_state.length} rooms.`);
};

export const createRoom = async (req, res) => {
  const prfx = 'Create Room:';
  const { name } = req.body;

  if (!name) {
    res.status(400).json({ error: 'Name is required.' });
    console.log(`${prfx} Name is required.`);
    return;
  }

  const room = { name, id: rooms_state.length + 1 };
  rooms_state.push(room);

  res.status(201).json(room);
  console.log(`${prfx} Created room "${name}".`);
};
