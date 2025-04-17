// src/utils/sanitize.ts
import { JSDOM } from 'jsdom';
import createDOMPurify from 'dompurify';

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

export const sanitize = (input: string): string => {
  return DOMPurify.sanitize(input);
};
