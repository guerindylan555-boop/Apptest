#!/usr/bin/env node

/**
 * Simple test script to verify health endpoints
 */

const http = require('http');

function makeRequest(path) {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();

    const req = http.get(`http://localhost:3001/api${path}`, (res) => {
      let data = '';

      res.on('data', (chunk) => {
        data += chunk;
      });

      res.on('end', () => {
        const responseTime = Date.now() - startTime;
        resolve({
          status: res.statusCode,
          headers: res.headers,
          data: data,
          responseTime: responseTime
        });
      });
    });

    req.on('error', (err) => {
      reject(err);
    });

    req.setTimeout(1000, () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
  });
}

async function testHealthEndpoints() {
  const endpoints = [
    '/healthz',
    '/health/ready',
    '/health/live',
    '/health/detailed'
  ];

  console.log('Testing Health Endpoints...\n');

  for (const endpoint of endpoints) {
    try {
      console.log(`Testing ${endpoint}...`);
      const result = await makeRequest(endpoint);

      console.log(`Status: ${result.status}`);
      console.log(`Response Time: ${result.responseTime}ms`);
      console.log(`Response Header - X-Response-Time: ${result.headers['x-response-time'] || 'N/A'}`);

      try {
        const parsedData = JSON.parse(result.data);
        console.log(`Health Status: ${parsedData.status}`);
        console.log(`Services: ${Object.keys(parsedData.services || {}).join(', ')}`);
      } catch (e) {
        console.log('Response:', result.data.substring(0, 100) + '...');
      }

      console.log('---');
    } catch (error) {
      console.log(`Error testing ${endpoint}: ${error.message}`);
      console.log('---');
    }
  }
}

// Run if called directly
if (require.main === module) {
  testHealthEndpoints().catch(console.error);
}

module.exports = { testHealthEndpoints };