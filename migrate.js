const { createClient } = require('@supabase/supabase-js');
const fs = require('fs');
const path = require('path');

require('dotenv').config();
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

const content = JSON.parse(fs.readFileSync(path.join(__dirname, 'content.json'), 'utf8'));
const contacts = JSON.parse(fs.readFileSync(path.join(__dirname, 'contacts.json'), 'utf8'));

async function migrate() {
  console.log('Migrating data to Supabase...\n');

  // Programs
  const programs = content.programs.map(p => ({
    id: p.id, badge: p.badge, badgeColor: p.badgeColor,
    badgeBorder: p.badgeBorder, badgeText: p.badgeText,
    icon: p.icon, title: p.title, description: p.desc
  }));
  const { error: e1 } = await supabase.from('programs').upsert(programs);
  console.log(e1 ? '✗ Programs: ' + e1.message : `✓ Programs: ${programs.length} rows`);

  // News
  const news = content.news.map(n => ({
    id: n.id, date: n.date, tag: n.tag, title: n.title, description: n.desc
  }));
  const { error: e2 } = await supabase.from('news').upsert(news);
  console.log(e2 ? '✗ News: ' + e2.message : `✓ News: ${news.length} rows`);

  // FAQ
  const faq = content.faq.map(f => ({ id: f.id, q: f.q, a: f.a }));
  const { error: e3 } = await supabase.from('faq').upsert(faq);
  console.log(e3 ? '✗ FAQ: ' + e3.message : `✓ FAQ: ${faq.length} rows`);

  // Events
  const events = content.events.map(ev => ({
    id: ev.id, year: ev.year, title: ev.title,
    date: ev.date, type: ev.type, description: ev.desc
  }));
  const { error: e4 } = await supabase.from('events').upsert(events);
  console.log(e4 ? '✗ Events: ' + e4.message : `✓ Events: ${events.length} rows`);

  // Team
  const team = content.team.map(t => ({
    id: t.id, name: t.name, role: t.role,
    category: t.category, initials: t.initials, photo: t.photo
  }));
  const { error: e5 } = await supabase.from('team').upsert(team);
  console.log(e5 ? '✗ Team: ' + e5.message : `✓ Team: ${team.length} rows`);

  // Hero
  const h = content.hero;
  const hero = [{
    id: 1, title: h.title, subtitle: h.subtitle,
    stat1_value: h.stat1.value, stat1_label: h.stat1.label,
    stat2_value: h.stat2.value, stat2_label: h.stat2.label,
    stat3_value: h.stat3.value, stat3_label: h.stat3.label
  }];
  const { error: e6 } = await supabase.from('hero').upsert(hero);
  console.log(e6 ? '✗ Hero: ' + e6.message : '✓ Hero: 1 row');

  // Contacts
  if (contacts.length) {
    const c = contacts.map(m => ({
      id: m.id, name: m.name, email: m.email, message: m.message,
      ip: m.ip, date: m.date, read: m.read
    }));
    const { error: e7 } = await supabase.from('contacts').upsert(c);
    console.log(e7 ? '✗ Contacts: ' + e7.message : `✓ Contacts: ${c.length} rows`);
  } else {
    console.log('✓ Contacts: empty (skipped)');
  }

  console.log('\nMigration complete!');
}

migrate().catch(console.error);
