const session = require('supertest-session');
const app = require('../../for_test');

describe('Auth Routes', () => {
  let testSession = null;
  let csrfToken = '';

  beforeAll(async () => {
    testSession = session(app);

    // Request the form to get the CSRF token
    const response = await testSession
      .get('/api/auth/csrf-token')
      .expect(200);

    ({ csrfToken } = response.body);
  });

  // test create user
  it('should register a new user', async () => {
    const response = await testSession
      .post('/api/auth/register')
      .set('X-CSRF-Token', csrfToken)
      .send({
        email: 'testmanjaaaaaatolol@example.com',
        password: 'pasasword',
        name: 'Test User',
      });

    expect(response.status).toBe(201);
    expect(response.body).toHaveProperty('user');
    expect(response.body.user).toHaveProperty('email', 'testmanjaaaaaatolol@example.com');
  });

  // test validation format
  it('should not register a user with invalid email', async () => {
    const response = await testSession
      .post('/api/auth/register')
      .set('X-CSRF-Token', csrfToken)
      .send({
        email: 'invalid-email',
        password: 'password',
        name: 'Test User',
      });

    expect(response.status).toBe(400);
    expect(response.body.errors[0]).toHaveProperty('msg', 'Invalid email format');
  });

  // test response existing user
  it('should login an existing user', async () => {
    const response = await testSession
      .post('/api/auth/login')
      .set('X-CSRF-Token', csrfToken)
      .send({
        email: 'test@example.com',
        password: 'password',
      });

    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty('user');
    expect(response.body.user).toHaveProperty('email', 'test@example.com');
    expect(response.body).toHaveProperty('token');
  });

  // Test incorrect credential response
  it('should not login a user with incorrect password', async () => {
    const response = await testSession
      .post('/api/auth/login')
      .set('X-CSRF-Token', csrfToken)
      .send({
        email: 'test@example.com',
        password: 'wrongpassword',
      });

    expect(response.status).toBe(401);
    expect(response.body).toHaveProperty('message', 'Invalid credentials');
  });

  // XSS Injection Test: Registration
  it('should not allow XSS injection in the name field during registration', async () => {
    const response = await testSession
      .post('/api/auth/register')
      .set('X-CSRF-Token', csrfToken)
      .send({
        email: 'xss@example.com',
        password: 'password',
        name: '<script>alert("XSS")</script>',
      });

    expect(response.status).toBe(400);
    expect(response.body).toHaveProperty('errors');
    expect(response.body.errors[0]).toHaveProperty('msg');
  });

  // XSS Injection Test: Login
  it('should not allow XSS injection in the email field during login', async () => {
    const response = await testSession
      .post('/api/auth/login')
      .set('X-CSRF-Token', csrfToken)
      .send({
        email: '<script>alert("XSS")</script>',
        password: 'password',
      });

    expect(response.status).toBe(400);
    expect(response.body).toHaveProperty('errors');
    expect(response.body.errors[0]).toHaveProperty('msg', 'Invalid email format');
  });

  // Frame Limit Test
  it('should have security headers to prevent framing', async () => {
    const response = await testSession
      .get('/api/auth/csrf-token')
      .expect(200);

    expect(response.headers).toHaveProperty('x-frame-options', 'DENY');
  });

  // SQL Injection Test
  it('should prevent SQL injection in the email field during login', async () => {
    const response = await testSession
      .post('/api/auth/login')
      .set('X-CSRF-Token', csrfToken)
      .send({
        email: "' OR '1'='1",
        password: 'password',
      });

    expect(response.status).toBe(400);
    expect(response.body.errors[0]).toHaveProperty('msg', 'Invalid email format');
  });

  // Password Policy Test
  it('should enforce password policy during registration', async () => {
    const response = await testSession
      .post('/api/auth/register')
      .set('X-CSRF-Token', csrfToken)
      .send({
        email: 'shortpass@example.com',
        password: '123',
        name: 'Test User',
      });

    expect(response.status).toBe(400);
    expect(response.body.errors[0]).toHaveProperty('msg', 'Password must be at least 6 characters');
  });

  // Security Headers Test
  it('should return 403 for invalid CSRF token', async () => {
    const response = await testSession
      .post('/api/auth/register')
      .set('X-CSRF-Token', 'invalid-csrf-token')
      .send({
        email: 'test@example.com',
        password: 'password',
        name: 'Test User',
      });

    expect(response.status).toBe(403);
    expect(response.body).toHaveProperty('message', 'invalid csrf token');
  });

  it('should have all necessary security headers', async () => {
    const response = await testSession
      .get('/api/auth/csrf-token')
      .expect(200);

    expect(response.headers).toHaveProperty('x-content-type-options', 'nosniff');
    expect(response.headers).toHaveProperty('x-frame-options', 'DENY');
    expect(response.headers).toHaveProperty('x-xss-protection', '1; mode=block');
    expect(response.headers).toHaveProperty('strict-transport-security');
    expect(response.headers).toHaveProperty('content-security-policy');
  });

  // Rate Limiting Test
  it('should limit the number of login attempts', async () => {
    const loginAttempts = Array.from({ length: 15 }, (_, i) => i);
    
    for (let i = 0; i < loginAttempts.length; i += 5) {
      const batch = loginAttempts.slice(i, i + 5);
  
      await Promise.all(batch.map(() => 
        testSession
          .post('/api/auth/login')
          .set('X-CSRF-Token', csrfToken)
          .send({ email: 'test@example.com', password: 'wrongpassword' })
      ));
    }
  
    const response = await testSession
      .post('/api/auth/login')
      .set('X-CSRF-Token', csrfToken)
      .send({ email: 'test@example.com', password: 'wrongpassword' });
  
    console.log(response.body);
  
    expect(response.status).toBe(429);
  });
});
