import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import dotenv from "dotenv";
import { MongoClient, ServerApiVersion, ObjectId } from "mongodb";
import { createRemoteJWKSet, jwtVerify } from "jose-cjs";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const port = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI as string;

const client = new MongoClient(MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// ---------- JWT verify (Better Auth JWKS) ----------
const JWKS = createRemoteJWKSet(
  new URL(`${process.env.CLIENT_URL}/api/auth/jwks`)
);

interface AuthedRequest extends Request {
  user?: any;
}

const verifyToken = async (req: AuthedRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer")) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  try {
    const { payload } = await jwtVerify(token, JWKS);
    req.user = payload;
    next();
  } catch (error) {
    return res.status(403).json({ message: "Forbidden" });
  }
};

// ---------- Item type ----------
interface Item {
  itemType: "lost" | "found";
  title: string;
  category: string;
  description: string;
  location: string;
  date: string;
  imageUrl?: string;
  contactName: string;
  contactNumber: string;
  status: "active" | "recovered";
  postedBy: string;
  createdAt: Date;
  updatedAt: Date;
}

async function run() {
  try {
    const db = client.db("lostlink");
    const itemsCollection = db.collection<Item>("items");

    // ---------- Routes ----------

    app.get("/api/items", async (req: Request, res: Response) => {
      try {
        const { search, category, itemType, status, page = "1", limit = "12" } = req.query;

        const matchQuery: Record<string, any> = {};
        if (search) matchQuery.title = { $regex: search as string, $options: "i" };
        if (category) matchQuery.category = category;
        if (itemType) matchQuery.itemType = itemType;
        if (status) matchQuery.status = status;

        const pageNum = Math.max(parseInt(page as string) || 1, 1);
        const limitNum = Math.max(parseInt(limit as string) || 12, 1);
        const skip = (pageNum - 1) * limitNum;

        const totalCount = await itemsCollection.countDocuments(matchQuery);
        const items = await itemsCollection
          .find(matchQuery)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limitNum)
          .toArray();

        res.send({
          items,
          totalCount,
          totalPages: Math.ceil(totalCount / limitNum),
          currentPage: pageNum,
        });
      } catch (error: any) {
        res.status(500).send({ message: "Failed to fetch items", error: error.message });
      }
    });

    app.get("/api/items/:id", async (req: Request, res: Response) => {
      try {
        const item = await itemsCollection.findOne({ _id: new ObjectId(req.params.id as string) });
        if (!item) return res.status(404).send({ message: "Item not found" });
        res.send(item);
      } catch (error: any) {
        res.status(500).send({ message: "Failed to fetch item", error: error.message });
      }
    });

    app.post("/api/items", verifyToken, async (req: AuthedRequest, res: Response) => {
      try {
        const newItem: Item = {
          ...req.body,
          status: "active",
          postedBy: req.user.id,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const result = await itemsCollection.insertOne(newItem);
        res.status(201).send({ success: true, insertedId: result.insertedId });
      } catch (error: any) {
         console.error("CREATE ITEM ERROR:", error);
        res.status(400).send({ message: "Failed to create item", error: error.message });
      }
    });

    app.get("/api/items/user/:userId", verifyToken, async (req: AuthedRequest, res: Response) => {
      try {
        const items = await itemsCollection
          .find({ postedBy: req.params.userId as string })
          .sort({ createdAt: -1 })
          .toArray();
        res.send(items);
      } catch (error: any) {
        res.status(500).send({ message: "Failed to fetch user items", error: error.message });
      }
    });

    app.patch("/api/items/:id", verifyToken, async (req: AuthedRequest, res: Response) => {
      try {
        const id = req.params.id as string;
        const existingItem = await itemsCollection.findOne({ _id: new ObjectId(id) });

        if (!existingItem) return res.status(404).send({ message: "Item not found" });
        if (existingItem.postedBy !== req.user.id) {
          return res.status(403).send({ message: "Not authorized to edit this item" });
        }

        const updateData = { ...req.body, updatedAt: new Date() };
        delete updateData._id;

        const result = await itemsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData }
        );
        res.send(result);
      } catch (error: any) {
        res.status(400).send({ message: "Failed to update item", error: error.message });
      }
    });

    app.delete("/api/items/:id", verifyToken, async (req: AuthedRequest, res: Response) => {
      try {
        const id = req.params.id as string;
        const existingItem = await itemsCollection.findOne({ _id: new ObjectId(id) });

        if (!existingItem) return res.status(404).send({ message: "Item not found" });
        if (existingItem.postedBy !== req.user.id) {
          return res.status(403).send({ message: "Not authorized to delete this item" });
        }

        const result = await itemsCollection.deleteOne({ _id: new ObjectId(id) });
        res.send(result);
      } catch (error: any) {
        res.status(500).send({ message: "Failed to delete item", error: error.message });
      }
    });
  } finally {
    // client.close(); // connection persistent রাখা হচ্ছে, তোমার FitZone-এর মতোই
  }
}

run().catch(console.dir);

app.get("/", (req: Request, res: Response) => {
  res.send("LostLink Server is running.......");
});

if (process.env.NODE_ENV !== "production") {
  app.listen(port, () => {
    console.log(`LostLink Server is running on port ${port}`);
  });
}