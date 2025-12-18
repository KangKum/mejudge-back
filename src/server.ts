import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import cron from "node-cron";

dotenv.config();

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);
const app = express();
const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 4000;

app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://mejudge.vercel.app", // ← 정확한 프론트 도메인
    ],
  })
);
app.use(express.json()); // JSON 파싱

//회원가입
app.post("/api/signup", async (req, res) => {
  const { id, password, nickname } = req.body;
  try {
    const existingUser = await userCollection.findOne({ id });
    if (existingUser) {
      return res.status(400).json({ message: "중복된 아이디입니다" });
    }

    const existingNickname = await userCollection.findOne({ nickname });
    if (existingNickname) {
      return res.status(401).json({ message: "중복된 닉네임입니다" });
    } else if (nickname.length < 2 || nickname.length > 8) {
      return res.status(402).json({ message: "닉네임은 2~8자여야 합니다" });
    } else if (!/^[가-힣a-zA-Z0-9]+$/.test(nickname)) {
      return res.status(403).json({ message: "닉네임은 한글, 영어, 숫자만 사용할 수 있습니다." });
    }

    // 비밀번호 해싱
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ id, pw: hashedPassword, nickname });
    res.status(200).json({ message: "회원가입이 완료되었습니다" });
  } catch (error) {
    res.status(500).json({ error: "회원가입 실패" });
  }
});

//로그인
app.post("/api/login", async (req, res) => {
  const { id, password } = req.body;
  try {
    // 1. 아이디/비밀번호 검증 (DB 등)
    const user = await userCollection.findOne({ id });
    if (!user) {
      return res.status(400).json({ message: "존재하지 않는 아이디입니다" });
    }
    const passwordMatch = await bcrypt.compare(password, user.pw);
    if (!passwordMatch) {
      return res.status(401).json({ message: "비밀번호가 일치하지 않습니다" });
    }
    // 2. JWT 생성
    const token = jwt.sign(
      { userId: user.id }, // payload: 필요한 정보
      JWT_SECRET, // 비밀키(환경변수로 관리)
      { expiresIn: "1d" } // 만료시간 등 옵션
    );
    // 3. 토큰과 닉네임 응답
    res.status(200).json({ token, nickname: user.nickname, isMJAdmin: user.isMJAdmin === "yesAdmin", message: "로그인 성공" });
  } catch (error) {
    res.status(500).json({ error: "로그인 실패" });
  }
});

//관리자 확인
app.get("/api/check-admin", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1]; // "Bearer <token>"
  if (!token) {
    return res.status(401).json({ message: "토큰이 제공되지 않았습니다" });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.userId;
    const user = await userCollection.findOne({ id: userId });
    if (!user) {
      return res.status(404).json({ message: "사용자를 찾을 수 없습니다" });
    }
    const isAdmin = user.isMJAdmin === "yesAdmin";
    res.status(200).json({ isAdmin });
  } catch (error) {
    res.status(401).json({ message: "유효하지 않은 토큰입니다" });
  }
});

//사건 등록
app.post("/api/case", async (req, res) => {
  const data = req.body;
  try {
    // 현재 가장 큰 caseNumber 조회
    const lastCase = await caseCollection.find().sort({ caseNumber: -1 }).limit(1).toArray();
    const nextCaseNumber = lastCase.length > 0 ? lastCase[0].caseNumber + 1 : 1;

    // 사건 데이터에 caseNumber 추가
    const caseData = { ...data, caseNumber: nextCaseNumber };

    await caseCollection.insertOne(caseData);
    res.status(201).json({ message: "사건이 성공적으로 등록되었습니다." });
  } catch (error) {
    res.status(500).json({ error: "사건 등록에 실패했습니다." });
  }
});
//사건 조회
app.get("/api/cases", async (req, res) => {
  const { type, userId } = req.query;
  let query = {};
  const projection = { _id: 1, caseNumber: 1, caseTitle: 1 };

  if (type === "done" && userId) {
    query = { sentencedUsers: userId };
  } else if (type === "undone" && userId) {
    query = { $or: [{ sentencedUsers: { $exists: false } }, { sentencedUsers: { $not: { $elemMatch: { $eq: userId } } } }] };
  }

  try {
    const cases = await caseCollection.find(query, { projection }).sort({ _id: -1 }).toArray();
    res.status(200).json(cases);
  } catch (error) {
    res.status(500).json({ error: "사건 목록 조회 실패" });
  }
});
//마지막 사건 조회
app.get("/api/cases/latest", async (req, res) => {
  try {
    const latestCase = await caseCollection.find().sort({ caseNumber: -1 }).limit(1).toArray();
    if (latestCase.length === 0) {
      return res.status(404).json({ message: "사건이 존재하지 않습니다." });
    }
    res.status(200).json(latestCase[0].caseNumber);
  } catch (error) {
    res.status(500).json({ error: "최신 사건 조회 실패" });
  }
});

//사건 페이지 진입(caseId)
app.get("/api/case/:caseId", async (req, res) => {
  const caseId = req.params.caseId;
  try {
    const caseData = await caseCollection.findOne({ _id: new ObjectId(caseId) });
    if (!caseData) {
      return res.status(404).json({ message: "해당 사건을 찾을 수 없습니다." });
    }
    res.status(200).json(caseData);
  } catch (error) {
    res.status(500).json({ error: "사건 조회 실패" });
  }
});

//이전 사건 조회
app.get("/api/pastCase/:caseNumber", async (req, res) => {
  const caseNumber = parseInt(req.params.caseNumber, 10);
  try {
    const caseData = await caseCollection.findOne({ caseNumber: caseNumber - 1 });
    if (!caseData) {
      return res.status(404).json({ message: "해당 사건을 찾을 수 없습니다." });
    }
    res.status(200).json(caseData._id);
  } catch (error) {
    res.status(500).json({ error: "사건 조회 실패" });
  }
});
//다음 사건 조회
app.get("/api/nextCase/:caseNumber", async (req, res) => {
  const caseNumber = parseInt(req.params.caseNumber, 10);
  try {
    const caseData = await caseCollection.findOne({ caseNumber: caseNumber + 1 });
    if (!caseData) {
      return res.status(404).json({ message: "해당 사건을 찾을 수 없습니다." });
    }
    res.status(200).json(caseData._id);
  } catch (error) {
    res.status(500).json({ error: "사건 조회 실패" });
  }
});

//판결 등록
app.post("/api/judgement/:userId/:caseId", async (req, res) => {
  const { userId, caseId } = req.params;
  const judgementData = req.body;

  let saveData = { userId, caseId, ...judgementData };
  if (judgementData.mode === 0) {
    saveData.fine = 0;
  } else if (judgementData.mode === 1) {
    saveData.year = 0;
    saveData.month = 0;
  }
  try {
    await judgementCollection.insertOne(saveData);

    // 사건 컬렉션에 sentencedUsers 배열에 userId 추가
    await caseCollection.updateOne({ _id: new ObjectId(caseId) }, { $addToSet: { sentencedUsers: userId } });

    res.status(201).json({ message: "판결이 성공적으로 등록되었습니다." });
  } catch (error) {
    res.status(500).json({ error: "판결 등록에 실패했습니다." });
  }
});
//판결 확인
app.get("/api/judgement/:userId/:caseId", async (req, res) => {
  const { userId, caseId } = req.params;

  try {
    const judgement = await judgementCollection.findOne({ userId, caseId });
    if (judgement) {
      res.status(200).json({ exists: true, judgement });
    } else {
      res.status(200).json({ exists: false, message: "판결이 존재하지 않습니다." }); //판결이 존재하지 않습니다.
    }
  } catch (error) {}
});
//판결 개수 조회(유저별)
app.get("/api/judgements/:userId", async (req, res) => {
  const { userId } = req.params;

  try {
    const judgements = await judgementCollection.find({ userId }).toArray();
    res.status(200).json(judgements.length);
  } catch (error) {
    res.status(500).json({ error: "판결 조회에 실패했습니다." });
  }
});

//댓글 등록
app.post("/api/comment/:userId/:caseId", async (req, res) => {
  const { userId, caseId } = req.params;
  const { comment, userNickname } = req.body;
  try {
    await commentCollection.insertOne({ userId, caseId, comment, userNickname, createdAt: new Date(), likes: [], dislikes: [] });
    res.status(201).json({ message: "댓글이 성공적으로 등록되었습니다." });
  } catch (error) {
    res.status(500).json({ error: "댓글 등록에 실패했습니다." });
  }
});
//댓글 전체 개수 조회
app.get("/api/comment/count/:caseId", async (req, res) => {
  const { caseId } = req.params;
  try {
    const comments = await commentCollection.find({ caseId }).toArray();
    res.status(200).json(comments.length);
  } catch (error) {
    res.status(500).json({ error: "댓글 조회에 실패했습니다." });
  }
});
//댓글 조회(케이스별)
app.get("/api/comment/:caseId", async (req, res) => {
  const { caseId } = req.params;
  const limit = parseInt(String(req.query.limit)) || 3; // 쿼리스트링에서 limit 받기
  try {
    const comments = await commentCollection
      .aggregate([
        { $match: { caseId } },
        { $addFields: { likesCount: { $size: { $ifNull: ["$likes", []] } } } },
        { $sort: { likesCount: -1, createdAt: -1 } },
        { $limit: limit },
      ])
      .toArray();
    res.status(200).json(comments);
  } catch (error) {
    res.status(500).json({ error: "댓글 조회에 실패했습니다." });
  }
});
//댓글 개수 조회(유저별)
app.get("/api/comments/:userId", async (req, res) => {
  const { userId } = req.params;

  try {
    const comments = await commentCollection.find({ userId }).toArray();
    res.status(200).json(comments.length);
  } catch (error) {
    res.status(500).json({ error: "댓글 조회에 실패했습니다." });
  }
});
//댓글 삭제
app.delete("/api/comment/delete/:commentId", async (req, res) => {
  const { commentId } = req.params;
  try {
    await commentCollection.deleteOne({ _id: new ObjectId(commentId) });
    res.status(200).json({ message: "댓글이 성공적으로 삭제되었습니다." });
  } catch (error) {
    res.status(500).json({ error: "댓글 삭제에 실패했습니다." });
  }
});
//받은 좋아요 수 조회(유저별)
app.get("/api/comment/likes/:userId", async (req, res) => {
  const { userId } = req.params;
  try {
    const likedComments = await commentCollection.find({ userId }).toArray();

    // 좋아요 수 전부 더하기
    const totalLikes = likedComments.reduce((sum, comment) => sum + (comment.likes ? comment.likes.length : 0), 0);
    res.status(200).json(totalLikes);
  } catch (error) {
    res.status(500).json({ error: "좋아요한 댓글 조회에 실패했습니다." });
  }
});
//받은 싫어요 수 조회(유저별)
app.get("/api/comment/dislikes/:userId", async (req, res) => {
  const { userId } = req.params;
  try {
    const dislikedComments = await commentCollection.find({ userId }).toArray();

    // 좋아요 수 전부 더하기
    const totaldisLikes = dislikedComments.reduce((sum, comment) => sum + (comment.dislikes ? comment.dislikes.length : 0), 0);
    res.status(200).json(totaldisLikes);
  } catch (error) {
    res.status(500).json({ error: "좋아요한 댓글 조회에 실패했습니다." });
  }
});
//좋아요 기능
app.post("/api/like/:commentId", async (req, res) => {
  const { commentId } = req.params;
  const { userId } = req.body;
  try {
    const comment = await commentCollection.findOne({ _id: new ObjectId(commentId) });
    if (!comment) {
      return res.status(404).json({ message: "해당 댓글을 찾을 수 없습니다." });
    }
    const hasLiked = Array.isArray(comment.likes) && comment.likes.includes(userId);

    if (hasLiked) {
      // 이미 좋아요를 눌렀다면 좋아요 취소
      await commentCollection.updateOne({ _id: new ObjectId(commentId) }, { $pull: { likes: userId } });
      res.status(200).json({ message: "좋아요가 취소되었습니다." });
    } else {
      // 좋아요 추가
      await commentCollection.updateOne({ _id: new ObjectId(commentId) }, { $addToSet: { likes: userId } });
      res.status(200).json({ message: "좋아요가 추가되었습니다." });
    }
  } catch (error) {
    res.status(500).json({ error: "좋아요 기능에 실패했습니다." });
  }
});
//싫어요 기능
app.post("/api/dislike/:commentId", async (req, res) => {
  const { commentId } = req.params;
  const { userId } = req.body;
  try {
    const comment = await commentCollection.findOne({ _id: new ObjectId(commentId) });
    if (!comment) {
      return res.status(404).json({ message: "해당 댓글을 찾을 수 없습니다." });
    }
    const hasDisliked = Array.isArray(comment.dislikes) && comment.dislikes.includes(userId);
    if (hasDisliked) {
      // 이미 좋아요를 눌렀다면 좋아요 취소
      await commentCollection.updateOne({ _id: new ObjectId(commentId) }, { $pull: { dislikes: userId } });
      res.status(200).json({ message: "싫어요가 취소되었습니다." });
    } else {
      // 좋아요 추가
      await commentCollection.updateOne({ _id: new ObjectId(commentId) }, { $addToSet: { dislikes: userId } });
      res.status(200).json({ message: "싫어요가 추가되었습니다." });
    }
  } catch (error) {
    res.status(500).json({ error: "싫어요 기능에 실패했습니다." });
  }
});

//비밀번호 변경
app.post("/api/users/change-password", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "토큰이 필요합니다." });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.userId;
    const { currentPassword, newPassword } = req.body;

    const user = await userCollection.findOne({ id: userId });
    if (!user) return res.status(400).json({ message: "사용자를 찾을 수 없습니다." });

    const passwordMatch = await bcrypt.compare(currentPassword, user.pw);
    if (!passwordMatch) return res.status(401).json({ message: "현재 비밀번호가 일치하지 않습니다." });

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    await userCollection.updateOne({ id: userId }, { $set: { pw: hashedNewPassword } });
    res.status(200).json({ message: "비밀번호가 성공적으로 변경되었습니다." });
  } catch (error) {
    res.status(500).json({ error: "비밀번호 변경에 실패했습니다." });
  }
});

//회원탈퇴
app.delete("/api/users/delete-account", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "토큰이 필요합니다." });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.userId;
    const { confirmPassword } = req.body;

    const user = await userCollection.findOne({ id: userId });
    if (!user) return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });

    const passwordMatch = await bcrypt.compare(confirmPassword, user.pw);
    if (!passwordMatch) return res.status(401).json({ message: "비밀번호가 일치하지 않습니다." });

    // 1. 유저 삭제
    await userCollection.deleteOne({ id: userId });

    // 2. 해당 유저가 작성한 댓글 삭제
    await commentCollection.deleteMany({ userId });

    // 3. 모든 댓글에서 likes, dislikes 배열에서 userId 제거
    await commentCollection.updateMany({ likes: userId }, { $pull: { likes: userId } });
    await commentCollection.updateMany({ dislikes: userId }, { $pull: { dislikes: userId } });

    // 4. 판결 삭제
    await judgementCollection.deleteMany({ userId });
    res.status(200).json({ message: "회원탈퇴가 성공적으로 완료되었습니다." });
  } catch (error) {
    res.status(500).json({ error: "회원탈퇴에 실패했습니다." });
  }
});

//랭킹 상위 10개 가져오기
app.get("/api/ranking/user-likes", async (req, res) => {
  try {
    const rankings = await rankingCollection
      .aggregate([
        {
          $lookup: {
            from: "user",
            localField: "userId",
            foreignField: "id",
            as: "userInfo",
          },
        },
        { $unwind: "$userInfo" },
        { $sort: { totalLikes: -1 } },
        { $limit: 10 },
        {
          $project: {
            userId: 1,
            totalLikes: 1,
            nickname: "$userInfo.nickname",
          },
        },
      ])
      .toArray();

    res.status(200).json(rankings);
  } catch (error) {
    res.status(500).json({ error: "랭킹 조회에 실패했습니다." });
  }
});

// node-cron을 이용한 집계 스케줄러 (하루 1회)
async function aggregateUserLikes() {
  try {
    // 유저별 좋아요 수 집계
    const results = await commentCollection
      .aggregate([{ $unwind: "$likes" }, { $group: { _id: "$userId", totalLikes: { $sum: 1 } } }, { $sort: { totalLikes: -1 } }])
      .toArray();

    // 기존 랭킹 데이터 초기화
    await rankingCollection.deleteMany({});

    // 집계 결과 저장
    if (results.length > 0) {
      await rankingCollection.insertMany(results.map((r) => ({ userId: r._id, totalLikes: r.totalLikes })));
    }
  } catch (err) {
    console.error("[user_likes_ranking] 집계 실패:", err);
  }
}

let userCollection;
let caseCollection;
let judgementCollection;
let commentCollection;
let rankingCollection;
async function startServer() {
  try {
    await client.connect();
    console.log("MongoDB 연결 성공");

    const db = client.db("mejudge"); // 예: "greenpen"
    userCollection = db.collection("user"); // 예: "users"
    caseCollection = db.collection("cases"); // 예: "cases"
    judgementCollection = db.collection("judgement"); // 예: "judgements"
    commentCollection = db.collection("comment"); // 예: "comments"
    rankingCollection = db.collection("userLikeRanking");

    // 매일 새벽 3시에 집계 실행 (서버 실행 중일 때)
    cron.schedule("0 3 * * *", aggregateUserLikes);
    // 서버 시작 시에도 1회 집계 (선택)
    aggregateUserLikes();

    app.listen(PORT, () => {
      console.log(`🚀 Server running on http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error("MongoDB 연결 실패:", err);
  }
}

startServer();
