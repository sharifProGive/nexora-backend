/* © 2026 Zentora CLC. All rights reserved. Platform Core engineered by Zentora. */
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// =========================================================================
// Zentora CLC 6-Vault Core Architecture (জিরো ডামি ডেটা নীতি)
// =========================================================================

// ২য় ঘর: Zentora Sharded Registry (মেটাডাটা ও চ্যানেল ডিরেক্টরি)
const ShardedRegistry = {
    users: new Map(),          // userId -> { nexoraId, handle, email, channelId }
    channels: new Map(),       // channelId -> { name, subscribers, verifiedBadge }
    videoMetadata: new Map(),  // videoId -> { title, description, category, tags, channelName }
    comments: new Map()        // videoId -> [ { commentId, author, text, timestamp } ]
};

// ৩য় ঘর: Zentora Metric Stream (ভিউ, ইন্টারঅ্যাকশন ও মেট্রিক্স)
const MetricStream = {
    viewCounters: new Map(),   // videoId -> Total Views
    engagement: new Map(),     // videoId -> { likes, dislikes, sparks }
    retentionLogs: new Map()   // videoId -> [ retentionScores ]
};

// ৪র্থ ঘর: Zentora Blobstore Vault (মূল ভিডিও ও থাম্বনেইল স্টোরেজ)
const BlobstoreVault = {
    videoBlobs: new Map(),     // videoId -> { streamUrl, duration, resolutionMap }
    thumbnailBlobs: new Map()  // videoId -> { originalThumbUrl, miniThumbUrl }
};

// ৫ম ঘর: Zentora Dedicated Ad Engine (ডেডিকেটেড বিজ্ঞাপন ভল্ট - নো ডামি ডেটা)
const DedicatedAdVault = {
    activeAds: new Map(),      // adId -> { title, sponsorName, adMediaUrl, clickThroughUrl, skippableAfterSeconds }
    adMetrics: new Map()       // adId -> { impressions, clicks, skips, completes }
};

// ৬ষ্ঠ মহা-ঘর: Zentora Grand Master Vault (সবার শীর্ষে থাকা চূড়ান্ত মাস্টার লেজার)
const GrandMasterVault = {
    immutableMasterLedger: [], // সর্বজনীন অপরিবর্তনীয় ট্রানজ্যাকশন ব্লক
    globalCrossIndex: new Map(), // entityId -> { ShardRef, MetricRef, BlobRef, AdRef }
    systemStateHash: ''
};

// ৬ষ্ঠ মহা-ঘরে সমস্ত ঘরের ডেটা সিঙ্ক ও লক করার সেন্ট্রাল প্রোটোকল
function anchorToGrandMaster(eventType, sourceVault, dataPayload) {
    const timestamp = Date.now();
    const transactionId = 'ZT-MASTER-' + crypto.randomBytes(8).toString('hex').toUpperCase();

    const block = {
        txId: transactionId,
        sourceVault: sourceVault,
        eventType: eventType,
        timestamp: timestamp,
        payload: dataPayload,
        vaultHash: crypto.createHash('sha256').update(JSON.stringify(dataPayload) + timestamp).digest('hex')
    };

    GrandMasterVault.immutableMasterLedger.push(block);
    GrandMasterVault.systemStateHash = block.vaultHash;
    return block;
}

// =========================================================================
// সেন্ট্রাল এপিআই রাউটস (Nexora Cloud Protocol - NCP)
// =========================================================================

// ১. সেন্ট্রাল হোম ফিড (জিরো ডামি ডেটা)
app.get('/api/v1/feed', (req, res) => {
    const publicFeed = [];

    for (let [videoId, meta] of ShardedRegistry.videoMetadata.entries()) {
        const metrics = MetricStream.engagement.get(videoId) || { likes: 0, dislikes: 0, sparks: 0 };
        const views = MetricStream.viewCounters.get(videoId) || 0;
        const media = BlobstoreVault.videoBlobs.get(videoId) || {};
        const thumb = BlobstoreVault.thumbnailBlobs.get(videoId) || {};

        publicFeed.push({
            id: videoId,
            ...meta,
            views: views,
            likes: metrics.likes,
            videoUrl: media.streamUrl,
            thumbnailUrl: thumb.originalThumbUrl
        });
    }

    res.json({ success: true, count: publicFeed.length, videos: publicFeed });
});

// ২. ভিডিও প্রকাশনা (ঘর ২ ও ৪-এ জমা করে ৬ষ্ঠ মহা-ঘরে চূড়ান্ত লক)
app.post('/api/v1/videos/publish', (req, res) => {
    const { title, description, category, tags, videoUrl, thumbnailUrl, channelName } = req.body;
    const videoId = 'NEX-' + Date.now();

    const metaRecord = { title, description, category: category || 'General', tags: tags || '', channelName };
    ShardedRegistry.videoMetadata.set(videoId, metaRecord);

    MetricStream.viewCounters.set(videoId, 0);
    MetricStream.engagement.set(videoId, { likes: 0, dislikes: 0, sparks: 0 });

    BlobstoreVault.videoBlobs.set(videoId, { streamUrl: videoUrl });
    BlobstoreVault.thumbnailBlobs.set(videoId, { originalThumbUrl: thumbnailUrl });

    GrandMasterVault.globalCrossIndex.set(videoId, {
        shardRef: metaRecord,
        metricRef: { views: 0, likes: 0 },
        blobRef: { videoUrl, thumbnailUrl }
    });

    const masterTx = anchorToGrandMaster('MASTER_VIDEO_INGESTED', 'VAULT_2_AND_4', { videoId, metaRecord });

    res.json({ success: true, message: 'Ingested and Locked into 6th Grand Master Vault', videoId, txId: masterTx.txId });
});

// ৩. রিয়েল-টাইম ইন্টারঅ্যাকশন
app.post('/api/v1/videos/interact', (req, res) => {
    const { videoId, action } = req.body;

    if (!MetricStream.engagement.has(videoId)) {
        return res.status(404).json({ success: false, message: 'Video not found in 3rd Metric Stream' });
    }

    const eng = MetricStream.engagement.get(videoId);
    if (action === 'like') eng.likes += 1;
    if (action === 'spark') eng.sparks += 1;
    if (action === 'view') {
        const currentViews = MetricStream.viewCounters.get(videoId) || 0;
        MetricStream.viewCounters.set(videoId, currentViews + 1);
    }

    MetricStream.engagement.set(videoId, eng);
    anchorToGrandMaster('INTERACTION_RECORDED', 'VAULT_3_METRIC_STREAM', { videoId, action });

    res.json({ success: true, views: MetricStream.viewCounters.get(videoId), engagement: eng });
});

// =========================================================================
// ৫ নম্বর ডেডিকেটেড বিজ্ঞাপন ভল্ট (Dedicated Ad Vault)
// =========================================================================

// ক. মোবাইল ব্রাউজার অ্যাডমিন পোর্টাল
app.get('/admin/ads', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="bn">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Nexora Ad Manager | 5th Vault</title>
            <style>
                body { background: #0b0e14; color: #f0f3f6; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 20px; margin: 0; }
                .box { max-width: 440px; margin: 20px auto; background: #161b22; padding: 24px; border-radius: 12px; border: 1px solid #30363d; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }
                h2 { margin-top: 0; color: #58a6ff; font-size: 1.3rem; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
                label { display: block; margin-top: 14px; font-size: 0.85rem; color: #8b949e; }
                input { width: 100%; padding: 12px; margin-top: 6px; border-radius: 8px; border: 1px solid #30363d; background: #0d1117; color: #fff; box-sizing: border-box; font-size: 0.95rem; }
                button { width: 100%; padding: 14px; margin-top: 22px; border-radius: 8px; border: none; background: #238636; color: #fff; font-size: 1rem; font-weight: bold; cursor: pointer; }
                .badge { background: #1f6feb; color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; vertical-align: middle; }
                .note { font-size: 0.75rem; color: #8b949e; margin-top: 14px; text-align: center; }
            </style>
        </head>
        <body>
            <div class="box">
                <h2>Nexora Ad Engine <span class="badge">5th Vault</span></h2>
                <form action="/api/v1/ads/upload" method="POST">
                    <label>Ad Campaign Title:</label>
                    <input type="text" name="title" placeholder="যেমন: Nike Promo Video" required />

                    <label>Sponsor / Company Name:</label>
                    <input type="text" name="sponsorName" placeholder="যেমন: Nike Sports" required />

                    <label>Original Ad Video Link (.mp4):</label>
                    <input type="url" name="adMediaUrl" placeholder="https://.../video.mp4" required />

                    <label>Company Website Link (Click-Through):</label>
                    <input type="url" name="clickThroughUrl" placeholder="https://nike.com" required />

                    <label>Skip Button Timer (Seconds):</label>
                    <input type="number" name="skippableAfterSeconds" value="5" min="1" max="30" />

                    <button type="submit">Deploy to 5th Ad Vault</button>
                </form>
                <div class="note">© 2026 Zentora CLC. Ingested directly into 6th Grand Master Vault.</div>
            </div>
        </body>
        </html>
    `);
});

// খ. ৫ নম্বর ভল্টে বিজ্ঞাপন আপলোড ও ৬ষ্ঠ মহা-ঘরে ট্রানজ্যাকশন লক
app.post('/api/v1/ads/upload', (req, res) => {
    const { title, sponsorName, adMediaUrl, clickThroughUrl, skippableAfterSeconds } = req.body;

    if (!adMediaUrl || !clickThroughUrl) {
        return res.status(400).json({ success: false, message: 'adMediaUrl and clickThroughUrl are required' });
    }

    const adId = 'ZT-AD-' + Date.now();
    const adData = {
        title: title || 'Direct Sponsor Ad',
        sponsorName: sponsorName || 'Direct Partner',
        adMediaUrl: adMediaUrl,
        clickThroughUrl: clickThroughUrl,
        skippableAfterSeconds: Number(skippableAfterSeconds) || 5
    };

    // ৫ নম্বর ঘরে সংরক্ষণ
    DedicatedAdVault.activeAds.set(adId, adData);
    DedicatedAdVault.adMetrics.set(adId, { impressions: 0, clicks: 0, skips: 0, completes: 0 });

    // ৬ষ্ঠ মহা-ঘরে ক্রিপ্টোগ্রাফিক লক
    const masterTx = anchorToGrandMaster('DIRECT_AD_INGESTED', 'VAULT_5_AD_ENGINE', { adId, adData });

    res.json({
        success: true,
        message: 'Original ad deployed to 5th Vault & locked into 6th Grand Master Vault',
        adId: adId,
        masterTxId: masterTx.txId
    });
});

// গ. অ্যান্ড্রয়েড প্লেয়ারের জন্য প্রি-রোল বিজ্ঞাপন সার্ভিস
app.get('/api/v1/ads/pre-roll', (req, res) => {
    const adEntries = Array.from(DedicatedAdVault.activeAds.entries());

    if (adEntries.length === 0) {
        return res.json({ success: true, hasAd: false, ad: null });
    }

    const [adId, adData] = adEntries[Math.floor(Math.random() * adEntries.length)];

    const metrics = DedicatedAdVault.adMetrics.get(adId);
    metrics.impressions += 1;
    DedicatedAdVault.adMetrics.set(adId, metrics);

    anchorToGrandMaster('AD_IMPRESSION', 'VAULT_5_AD_ENGINE', { adId });

    res.json({
        success: true,
        hasAd: true,
        ad: {
            adId: adId,
            title: adData.title,
            sponsorName: adData.sponsorName,
            adMediaUrl: adData.adMediaUrl,
            clickThroughUrl: adData.clickThroughUrl,
            skippableAfterSeconds: adData.skippableAfterSeconds
        }
    });
});

// ঘ. বিজ্ঞাপন মেট্রিক্স ট্র্যাকিং (ক্লিক, স্কিপ, কম্প্লিট)
app.post('/api/v1/ads/track', (req, res) => {
    const { adId, action } = req.body;

    if (!DedicatedAdVault.adMetrics.has(adId)) {
        return res.status(404).json({ success: false, message: 'Ad not found in 5th Ad Vault' });
    }

    const metrics = DedicatedAdVault.adMetrics.get(adId);
    if (action === 'click') metrics.clicks += 1;
    if (action === 'skip') metrics.skips += 1;
    if (action === 'complete') metrics.completes += 1;

    DedicatedAdVault.adMetrics.set(adId, metrics);
    anchorToGrandMaster(`AD_${action.toUpperCase()}`, 'VAULT_5_AD_ENGINE', { adId });

    res.json({ success: true, metrics: metrics });
});

// =========================================================================
// ৬ষ্ঠ মহা-ঘরের সার্বিক অডিট ও সিস্টেম হেলথ চেক
// =========================================================================
app.get('/api/v1/vaults/audit', (req, res) => {
    res.json({
        platform: 'Nexora Stream',
        organization: 'Zentora CLC',
        developer: 'Zentora',
        vault_1_device_storage: 'Android Room DB (Synchronized)',
        vault_2_sharded_metadata_count: ShardedRegistry.videoMetadata.size,
        vault_3_metric_stream_records: MetricStream.viewCounters.size,
        vault_4_blobstore_items: BlobstoreVault.videoBlobs.size,
        vault_5_dedicated_ad_engine_active_ads: DedicatedAdVault.activeAds.size,
        vault_6_grand_master_total_blocks: GrandMasterVault.immutableMasterLedger.length,
        systemIntegrityHash: GrandMasterVault.systemStateHash
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Zentora 6-Vault Core Engine active on port ${PORT}`);
});
