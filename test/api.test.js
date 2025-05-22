const request = require('supertest');
const app = require('../index.js');
const mongoose = require('mongoose');

beforeAll(async () => {
  // Optional: connect to a test database if needed
});

afterAll(async () => {
  await mongoose.connection.close();
});

describe('POST /register', () => {
  it('should return 200 for valid email', async () => {
    const res = await request(app)
      .post('/register')
      .send({ email: `test${Date.now()}@example.com` });
    expect(res.statusCode).toBe(200);
    expect(res.text).toMatch(/Verification email sent/i);
  });

  // it('should return 400 for duplicate email', async () => {
  //   const email = `duptest${Date.now()}@example.com`;

  //   await request(app).post('/register').send({ email });

  //   const res = await request(app).post('/register').send({ email });
  //   expect(res.statusCode).toBe(400);
  //   expect(res.text).toMatch(/already registered/i);
  // });
});

describe('POST /login', () => {
  const email = `login${Date.now()}@example.com`;
  const password = 'testpass123';

  it('should fail if unregistered', async () => {
    const res = await request(app)
      .post('/login')
      .send({ email: 'fake@example.com', password: 'wrong' });

    expect(res.statusCode).toBe(401);
    expect(res.body.message).toMatch(/Invalid credentials/i);
  });

  it('should work after verification', async () => {
    // Register & Verify Manually (simulated)
    const token = require('jsonwebtoken').sign({ email }, 'HONORS', { expiresIn: '15m' });
    await request(app)
      .post('/verify-registration?token=' + token)
      .send({ password });

    const res = await request(app)
      .post('/login')
      .send({ email, password });

    expect(res.statusCode).toBe(200);
    expect(res.body.message).toMatch(/Login successful/i);
    expect(res.body.token).toBeDefined();
  });
});

describe('POST /request-reset', () => {
  it('should send reset email for existing user', async () => {
    const email = `reset${Date.now()}@example.com`;
    const password = 'reset123';

    // Register & verify
    const token = require('jsonwebtoken').sign({ email }, 'HONORS', { expiresIn: '15m' });
    await request(app)
      .post('/verify-registration?token=' + token)
      .send({ password });

    const res = await request(app)
      .post('/request-reset')
      .send({ email });

    expect(res.statusCode).toBe(200);
    expect(res.body.message).toMatch(/Password reset link sent/i);
  });
});
