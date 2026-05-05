import { connect } from "mongoose";
import config from "./config.js";

export default async function connectDB() {
  await connect(config.MONGO_URI);

  console.log("Connected to DB");
}
