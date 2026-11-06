require('dotenv').config();
const pool = require('../src/config/db');

async function inspectData() {
  console.log('\n========================================================');
  console.log('       📊 SMART SCHOOL ERP — BACKEND DATABASE VIEWER     ');
  console.log('========================================================\n');

  try {
    const tenants = await pool.query('SELECT id, name, slug, school_code, status, currency FROM tenants');
    console.log(`🏫 Schools / Tenants (${tenants.rowCount}):`);
    console.table(tenants.rows);

    const users = await pool.query('SELECT id, tenant_id, full_name, email, role, is_active FROM users ORDER BY id ASC');
    console.log(`\n👤 Users (${users.rowCount}):`);
    console.table(users.rows);

    const tables = [
      'students', 'parents', 'staff', 'class_masters', 'sections',
      'fee_categories', 'fee_structures', 'payments', 'admission_applications',
      'inventory_items', 'books', 'routes', 'hostels', 'lms_courses'
    ];

    const counts = [];
    for (const table of tables) {
      try {
        const res = await pool.query(`SELECT count(*) FROM "${table}"`);
        counts.push({ Table: table, TotalRows: Number(res.rows[0].count) });
      } catch {
        // skip if not existing
      }
    }

    console.log('\n📈 Module Data Summary:');
    console.table(counts);

    console.log('\n💡 Tip: To query specific tables, you can run:');
    console.log('   psql -U postgres -d school_erp');
    console.log('   or open pgAdmin 4 from your Start Menu.\n');

  } catch (err) {
    console.error('Failed to query database:', err.message);
  } finally {
    await pool.end();
  }
}

inspectData();
