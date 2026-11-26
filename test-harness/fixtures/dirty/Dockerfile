# Dirty fixture Dockerfile: root user (no USER instruction), :latest base
# image, and a secret baked into a layer. All values are FAKE.
FROM node:latest
ENV STRIPE_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc
RUN npm install
CMD ["node", "index.js"]
