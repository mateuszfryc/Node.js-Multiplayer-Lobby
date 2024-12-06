// the most aggressive sanitization function, removes all non-alphanumeric characters
export const steriliseText = (text) => {
  return text.replace(/[^a-zA-Z0-9]/g, '');
};
