import sodium from 'sodium-native';

// Define a buffer to hold the key
const key = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES); // Length depends on the algorithm

// Generate a random key
sodium.randombytes_buf(key);

// Print the key in Base64 format for easier storage/display
console.log('Generated SODIUM_KEY:', key.toString('base64'));
