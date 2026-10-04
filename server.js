// © 2026 Zentora CLC. All rights reserved.
// Platform Core engineered by Zentora.
const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());

let globalVideos = [];

app.get('/api/videos/feed', (req, res) => {
    res.json({ success: true, videos: globalVideos });
});

app.post('/api/videos/upload', (req, res) => {
    const { title, description, category, videoUrl, thumbnailUrl, channelName } = req.body;
    const newVideo = {
        id: 'nex_' + Date.now(),
        title: title || 'Untitled Stream',
        description: description || '',
        category: category || 'All',
        videoUrl: videoUrl,
        thumbnailUrl: thumbnailUrl,
        channelName: channelName || 'Zentora Creator',
        views: 0,
        likes: 0,
        timestamp: Date.now()
    };
    globalVideos.unshift(newVideo);
    res.json({ success: true, video: newVideo });
});

app.post('/api/videos/like', (req, res) => {
    const { videoId } = req.body;
    const target = globalVideos.find(v => v.id === videoId);
    if (target) {
        target.likes += 1;
        return res.json({ success: true, likes: target.likes });
    }
    res.status(404).json({ success: false, message: 'Video not found' });
});

app.get('/api/videos/search', (req, res) => {
    const query = (req.query.q || '').toLowerCase();
    const results = globalVideos.filter(v => 
        v.title.toLowerCase().includes(query) || 
        v.category.toLowerCase().includes(query)
    );
    res.json({ success: true, results });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Nexora Cloud Core Engine active on port ${PORT}`);
});
