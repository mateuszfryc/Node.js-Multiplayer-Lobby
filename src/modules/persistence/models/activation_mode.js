export class ActivationModel {
  constructor(model) {
    this.model = model;
  }
  async create(data) {
    return this.model.create(data);
  }
  async findByToken(token) {
    return this.model.findOne({ where: { token } });
  }

  async invalidate(token) {
    return this.model.destroy({ where: { token } });
  }
}
