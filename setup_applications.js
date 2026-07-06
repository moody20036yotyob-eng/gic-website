// Run once: node setup_applications.js
// Creates the applications table in Supabase

const { createClient } = require('@supabase/supabase-js');

require('dotenv').config();
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const db = createClient(SUPABASE_URL, SUPABASE_KEY);

async function setup() {
  console.log('Testing connection...');

  // Insert a test row to check if table exists
  const { error: checkErr } = await db.from('applications').select('id').limit(1);

  if (!checkErr) {
    console.log('✓ applications table already exists');
    return;
  }

  console.log('Table does not exist. Please run this SQL in your Supabase dashboard:');
  console.log('');
  console.log('Go to: https://supabase.com → Your Project → SQL Editor → New Query');
  console.log('');
  console.log(`
CREATE TABLE IF NOT EXISTS applications (
  id bigserial PRIMARY KEY,
  name text NOT NULL,
  email text NOT NULL,
  student_id text DEFAULT '',
  major text DEFAULT '',
  year_level text DEFAULT '',
  program text NOT NULL,
  message text DEFAULT '',
  status text DEFAULT 'pending',
  ip text DEFAULT '',
  date timestamptz DEFAULT now(),
  read boolean DEFAULT false
);
  `.trim());
  console.log('');
  console.log('After running the SQL, restart your server (Ctrl+C then node server.js)');
}

setup().catch(console.error);
