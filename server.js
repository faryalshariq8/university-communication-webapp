
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const DATA_FILE = path.join(__dirname, "data.json");

function hashPassword(password, salt) {
    return crypto.scryptSync(password, salt, 64).toString("hex");
}

function makePassword(password) {
    const salt = crypto.randomBytes(16).toString("hex");
    return {
        salt,
        passwordHash: hashPassword(password, salt)
    };
}


function checkPassword(password, user) {
    if (!user || !user.salt || !user.passwordHash) {
        return false;
    }

    const hash = Buffer.from(hashPassword(password, user.salt), "hex");
    const original = Buffer.from(user.passwordHash, "hex");

    return hash.length === original.length &&
        crypto.timingSafeEqual(hash, original);
}

function createInitialData() {
    const adminPassword = makePassword("Admin123!");
    const aliPassword = makePassword("Ali123!");
    const saraPassword = makePassword("Sara123!");
    const ahmedPassword = makePassword("Ahmed123!");

    return {
        nextUserId: 5,
        users: [
            {
                id: 1, name: "Ali", username: "ali",
                role: "Student", department: "CS",
                courses: ["CS101"], ...aliPassword
            },
            {
                id: 2, name: "Sara", username: "sara",
                role: "Faculty", department: "CS",
                courses: ["CS101"], ...saraPassword
            },
            {
                id: 3, name: "Ahmed", username: "ahmed",
                role: "Student", department: "EE",
                courses: ["EE101"], ...ahmedPassword
            },
            {
                id: 4, name: "Administrator", username: "admin",
                role: "Admin", department: "Administration",
                courses: [], ...adminPassword
            }
        ],
        groups: [
            {
                id: "bscs-a",
                name: "BSCS Section A",
                type: "General",
                courseCode: "",
                members: [1, 2]
            },
            {
                id: "cs-faculty",
                name: "CS Faculty",
                type: "General",
                courseCode: "",
                members: [2]
            },
            {
                id: "fyp-team",
                name: "FYP Team",
                type: "General",
                courseCode: "",
                members: [1, 2]
            },
            {
                id: "course-cs101",
                name: "Introduction to Computing",
                type: "Course",
                courseCode: "CS101",
                members: [1, 2]
            },
            {
                id: "course-ee101",
                name: "Electrical Engineering Basics",
                type: "Course",
                courseCode: "EE101",
                members: [3]
            }
        ],
        messages: [],
        announcements: [],
        nextAnnouncementId: 1
    };
}

let data;

if (fs.existsSync(DATA_FILE)) {
    data = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
} else {
    data = createInitialData();
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

function saveData() {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

function publicUser(user) {
    return {
        id: user.id,
        name: user.name,
        username: user.username,
        role: user.role,
        department: user.department,
        courses: user.courses
    };
}

function currentUser(req) {
    return data.users.find(user => user.id === req.session.userId);
}

function requireLogin(req, res, next) {
    if (!currentUser(req)) {
        return res.status(401).json({ error: "Please log in first." });
    }
    next();
}

function requireAdmin(req, res, next) {
    if (!currentUser(req) || currentUser(req).role !== "Admin") {
        return res.status(403).json({
            error: "Only an administrator can perform this action."
        });
    }
    next();
}

function canAccessGroup(user, group) {
    return user.role === "Admin" || group.members.includes(user.id);
}

function makeId(prefix) {
    return prefix + "-" + crypto.randomUUID();
}

app.use(express.json());

const sessionMiddleware = session({
    secret: process.env.SESSION_SECRET || "change-this-local-lab-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: false,
        maxAge: 1000 * 60 * 60 * 8
    }
});

app.use(sessionMiddleware);
app.use(express.static(path.join(__dirname, "public")));

io.engine.use(sessionMiddleware);

io.use((socket, next) => {
    const userId = socket.request.session.userId;
    const user = data.users.find(item => item.id === userId);

    if (!user) {
        return next(new Error("Please log in first."));
    }

    socket.data.userId = user.id;
    next();
});

app.post("/api/login", (req, res, next) => {
    const username = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const user = data.users.find(item =>
        item.username.toLowerCase() === username
    );

    if (!user || !checkPassword(password, user)) {
        return res.status(401).json({
            error: "Incorrect username or password."
        });
    }

    req.session.regenerate(error => {
        if (error) {
            return next(error);
        }

        req.session.userId = user.id;

        req.session.save(error => {
            if (error) {
                return next(error);
            }

            res.json({ user: publicUser(user) });
        });
    });
});

app.post("/api/logout", requireLogin, (req, res, next) => {
    const userId = req.session.userId;

    for (const socket of io.sockets.sockets.values()) {
        if (socket.data.userId === userId) {
            socket.disconnect(true);
        }
    }

    req.session.destroy(error => {
        if (error) {
            return next(error);
        }

        res.clearCookie("connect.sid");
        res.json({ message: "Logged out." });
    });
});

app.get("/api/me", requireLogin, (req, res) => {
    res.json({ user: publicUser(currentUser(req)) });
});

app.get("/api/data", requireLogin, (req, res) => {
    const user = currentUser(req);
    const visibleGroups = data.groups.filter(group =>
        canAccessGroup(user, group)
    );

    const visibleAnnouncements = data.announcements.filter(item =>
        item.groupId === "all" ||
        visibleGroups.some(group => group.id === item.groupId)
    );

    res.json({
        user: publicUser(user),
        users: user.role === "Admin" ? data.users.map(publicUser) : [],
        groups: visibleGroups,
        announcements: visibleAnnouncements
    });
});

app.post("/api/users", requireLogin, requireAdmin, (req, res) => {
    const name = String(req.body.name || "").trim();
    const username = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const role = req.body.role;
    const department = String(req.body.department || "").trim();
    const courses = Array.isArray(req.body.courses)
        ? [...new Set(req.body.courses.map(code =>
            String(code).trim().toUpperCase()
        ).filter(Boolean))]
        : [];

    if (!name || !/^[a-z0-9._-]{3,30}$/.test(username) ||
        password.length < 8 || !department ||
        !["Student", "Faculty", "Admin"].includes(role)) {
        return res.status(400).json({
            error: "Enter valid details. Username must be 3–30 characters and password at least 8 characters."
        });
    }

    if (data.users.some(user => user.username.toLowerCase() === username)) {
        return res.status(409).json({ error: "That username already exists." });
    }

    const passwordData = makePassword(password);

    const user = {
        id: data.nextUserId++,
        name,
        username,
        role,
        department,
        courses,
        ...passwordData
    };

    data.users.push(user);
    saveData();

    res.json({ user: publicUser(user) });
});

app.post("/api/groups", requireLogin, requireAdmin, (req, res) => {
    const name = String(req.body.name || "").trim();
    const type = req.body.type === "Course" ? "Course" : "General";
    const courseCode = String(req.body.courseCode || "").trim().toUpperCase();
    const members = Array.isArray(req.body.members)
        ? [...new Set(req.body.members.map(Number))]
        : [];

    if (!name) {
        return res.status(400).json({ error: "Enter a group name." });
    }

    if (type === "Course" && !courseCode) {
        return res.status(400).json({
            error: "Enter a course code for a course group."
        });
    }

    if (members.some(id => !data.users.some(user => user.id === id))) {
        return res.status(400).json({ error: "Invalid group member." });
    }

    if (type === "Course" && members.some(id => {
        const user = data.users.find(item => item.id === id);
        return user.role !== "Admin" && !user.courses.includes(courseCode);
    })) {
        return res.status(400).json({
            error: "Course groups can only include users assigned that course. Update their course list first."
        });
    }

    const group = {
        id: makeId("group"),
        name,
        type,
        courseCode: type === "Course" ? courseCode : "",
        members
    };

    data.groups.push(group);
    saveData();

    res.json({ group });
});

app.put("/api/groups/:id/members", requireLogin, requireAdmin, (req, res) => {
    const group = data.groups.find(item => item.id === req.params.id);

    if (!group) {
        return res.status(404).json({ error: "Group not found." });
    }

    if (!Array.isArray(req.body.members)) {
        return res.status(400).json({ error: "Provide a member list." });
    }

    const members = [...new Set(req.body.members.map(Number))];

    if (members.some(id => !data.users.some(user => user.id === id))) {
        return res.status(400).json({ error: "Invalid group member." });
    }

    if (group.type === "Course" && members.some(id => {
        const user = data.users.find(item => item.id === id);
        return user.role !== "Admin" &&
            !user.courses.includes(group.courseCode);
    })) {
        return res.status(400).json({
            error: "A user must be assigned " + group.courseCode + " before joining this course group."
        });
    }

    group.members = members;
    saveData();

    for (const socket of io.sockets.sockets.values()) {
        if (socket.data.groupId === group.id &&
            !group.members.includes(socket.data.userId)) {
            socket.leave(group.id);
            socket.data.groupId = null;
            socket.emit("access-revoked", {
                groupId: group.id,
                message: "Your access to " + group.name + " has been removed."
            });
        }
    }

    res.json({ group });
});

app.get("/api/groups/:id/messages", requireLogin, (req, res) => {
    const user = currentUser(req);
    const group = data.groups.find(item => item.id === req.params.id);

    if (!group || !canAccessGroup(user, group)) {
        return res.status(403).json({ error: "You cannot access this group." });
    }

    const messages = data.messages.filter(item => item.groupId === group.id);
    res.json({ messages });
});

app.post("/api/announcements", requireLogin, requireAdmin, (req, res) => {
    const title = String(req.body.title || "").trim();
    const message = String(req.body.message || "").trim();
    const groupId = String(req.body.groupId || "all");

    if (!title || !message || title.length > 120 || message.length > 3000) {
        return res.status(400).json({
            error: "Enter a title (max 120 characters) and message (max 3000 characters)."
        });
    }

    if (groupId !== "all" &&
        !data.groups.some(group => group.id === groupId)) {
        return res.status(400).json({ error: "Select a valid group." });
    }

    const announcement = {
        id: data.nextAnnouncementId++,
        title,
        message,
        groupId,
        sender: currentUser(req).name,
        time: new Date().toISOString()
    };

    data.announcements.push(announcement);
    saveData();

    if (groupId === "all") {
        io.emit("new-announcement", announcement);
    } else {
        const group = data.groups.find(item => item.id === groupId);

        group.members.forEach(userId => {
            io.to("user:" + userId).emit("new-announcement", announcement);
        });
    }

    res.json({ announcement });
});

io.on("connection", socket => {
    socket.join("user:" + socket.data.userId);
    socket.on("join-group", groupId => {
        const user = data.users.find(item => item.id === socket.data.userId);
        const group = data.groups.find(item => item.id === groupId);

        if (!user || !group || !canAccessGroup(user, group)) {
            socket.emit("error-message", "You are not allowed to join this group.");
            return;
        }

        for (const room of [...socket.rooms]) {
            if (room !== socket.id && !room.startsWith("user:")) {
                socket.leave(room);
            }
        }

        socket.data.groupId = group.id;
        socket.join(group.id);

        socket.emit("joined-group", {
            groupId: group.id,
            name: group.name
        });
    });

    socket.on("send-message", text => {
        const user = data.users.find(item => item.id === socket.data.userId);
        const group = data.groups.find(item => item.id === socket.data.groupId);

        if (!user || !group || !canAccessGroup(user, group)) {
            socket.emit("error-message", "Join an authorized group first.");
            return;
        }

        const messageText = String(text || "").trim();

        if (!messageText || messageText.length > 1000) {
            socket.emit("error-message", "Messages must contain 1–1000 characters.");
            return;
        }

        const message = {
            id: makeId("message"),
            groupId: group.id,
            senderId: user.id,
            sender: user.name,
            text: messageText,
            time: new Date().toISOString()
        };

        data.messages.push(message);
        saveData();
        io.to(group.id).emit("new-message", message);
    });
});

server.listen(3000, () => {
    console.log("CampusLoop running at http://localhost:3000");
});