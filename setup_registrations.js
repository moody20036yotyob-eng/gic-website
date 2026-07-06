// Run once: node setup_registrations.js
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const db = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

async function setup() {
  const { error } = await db.from('event_registrations').select('id').limit(1);
  if (!error) { console.log('✓ event_registrations table already exists'); return; }
  console.log('Table does not exist. Run this SQL in Supabase SQL Editor:\n');
  console.log(`
CREATE TABLE IF NOT EXISTS event_registrations (
  id bigserial PRIMARY KEY,
  event_title text NOT NULL,
  name text NOT NULL,
  email text NOT NULL,
  student_id text DEFAULT '',
  message text DEFAULT '',
  status text DEFAULT 'pending',
  ip text DEFAULT '',
  date timestamptz DEFAULT now(),
  read boolean DEFAULT false
);
  `.trim());
}
setup().catch(console.error);
