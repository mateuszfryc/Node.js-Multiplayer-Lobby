export class ActivationModel {
  constructor(model) {
    this.model = model;
  }
  async createActivation(data) {
    return this.model.create(data);
  }
  async findByToken(token) {
    return this.model.findOne({ where: { token } });
  }
}
