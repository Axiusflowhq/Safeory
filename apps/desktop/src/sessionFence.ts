export class SessionFence {
  #generation = 0;

  token() {
    return this.#generation;
  }

  invalidate() {
    this.#generation += 1;
    return this.#generation;
  }

  accepts(token: number) {
    return token === this.#generation;
  }
}
