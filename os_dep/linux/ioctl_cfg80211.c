/******************************************************************************
 *
 * Copyright(c) 2007 - 2019 Realtek Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 *****************************************************************************/
#define  _IOCTL_CFG80211_C_

#include <drv_types.h>
#include <hal_data.h>

#ifdef CONFIG_IOCTL_CFG80211

#ifndef DBG_RTW_CFG80211_STA_PARAM
#define DBG_RTW_CFG80211_STA_PARAM 0
#endif

#ifndef DBG_RTW_CFG80211_MESH_CONF
#define DBG_RTW_CFG80211_MESH_CONF 0
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0))
#define STATION_INFO_INACTIVE_TIME	BIT(NL80211_STA_INFO_INACTIVE_TIME)
#define STATION_INFO_LLID		BIT(NL80211_STA_INFO_LLID)
#define STATION_INFO_PLID		BIT(NL80211_STA_INFO_PLID)
#define STATION_INFO_PLINK_STATE	BIT(NL80211_STA_INFO_PLINK_STATE)
#define STATION_INFO_SIGNAL		BIT(NL80211_STA_INFO_SIGNAL)
#define STATION_INFO_TX_BITRATE		BIT(NL80211_STA_INFO_TX_BITRATE)
#define STATION_INFO_RX_PACKETS		BIT(NL80211_STA_INFO_RX_PACKETS)
#define STATION_INFO_TX_PACKETS		BIT(NL80211_STA_INFO_TX_PACKETS)
#define STATION_INFO_TX_FAILED		BIT(NL80211_STA_INFO_TX_FAILED)
#define STATION_INFO_LOCAL_PM		BIT(NL80211_STA_INFO_LOCAL_PM)
#define STATION_INFO_PEER_PM		BIT(NL80211_STA_INFO_PEER_PM)
#define STATION_INFO_NONPEER_PM		BIT(NL80211_STA_INFO_NONPEER_PM)
#define STATION_INFO_ASSOC_REQ_IES	0
#endif /* Linux kernel >= 4.0.0 */

#define RTW_MAX_MGMT_TX_CNT (8)
#define RTW_MAX_MGMT_TX_MS_GAS (500)

#define RTW_SCAN_IE_LEN_MAX      2304
#define RTW_MAX_REMAIN_ON_CHANNEL_DURATION 5000 /* ms */
#define RTW_MAX_NUM_PMKIDS 4

#define RTW_CH_MAX_2G_CHANNEL               14      /* Max channel in 2G band */

#ifdef CONFIG_WAPI_SUPPORT

#ifndef WLAN_CIPHER_SUITE_SMS4
#define WLAN_CIPHER_SUITE_SMS4          0x00147201
#endif

#ifndef WLAN_AKM_SUITE_WAPI_PSK
#define WLAN_AKM_SUITE_WAPI_PSK         0x000FAC04
#endif

#ifndef WLAN_AKM_SUITE_WAPI_CERT
#define WLAN_AKM_SUITE_WAPI_CERT        0x000FAC12
#endif

#ifndef NL80211_WAPI_VERSION_1
#define NL80211_WAPI_VERSION_1          (1 << 2)
#endif

#endif /* CONFIG_WAPI_SUPPORT */

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(4, 11, 12))
#ifdef CONFIG_RTW_80211R
#define WLAN_AKM_SUITE_FT_8021X		0x000FAC03
#define WLAN_AKM_SUITE_FT_PSK			0x000FAC04
#endif
#endif

#define WIFI_CIPHER_SUITE_GCMP		0x000FAC08
#define WIFI_CIPHER_SUITE_GCMP_256	0x000FAC09
#define WIFI_CIPHER_SUITE_CCMP_256	0x000FAC0A
#define WIFI_CIPHER_SUITE_BIP_GMAC_128	0x000FAC0B
#define WIFI_CIPHER_SUITE_BIP_GMAC_256	0x000FAC0C
#define WIFI_CIPHER_SUITE_BIP_CMAC_256	0x000FAC0D

/*
 * If customer need, defining this flag will make driver 
 * always return -EBUSY at the condition of scan deny.
 */
/* #define CONFIG_NOTIFY_SCAN_ABORT_WITH_BUSY */

static const u32 rtw_cipher_suites[] = {
	WLAN_CIPHER_SUITE_WEP40,
	WLAN_CIPHER_SUITE_WEP104,
	WLAN_CIPHER_SUITE_TKIP,
	WLAN_CIPHER_SUITE_CCMP,
#ifdef CONFIG_WAPI_SUPPORT
	WLAN_CIPHER_SUITE_SMS4,
#endif /* CONFIG_WAPI_SUPPORT */
#ifdef CONFIG_IEEE80211W
	WLAN_CIPHER_SUITE_AES_CMAC,
	WIFI_CIPHER_SUITE_GCMP,
	WIFI_CIPHER_SUITE_GCMP_256,
	WIFI_CIPHER_SUITE_CCMP_256,
	WIFI_CIPHER_SUITE_BIP_GMAC_128,
	WIFI_CIPHER_SUITE_BIP_GMAC_256,
	WIFI_CIPHER_SUITE_BIP_CMAC_256,
#endif /* CONFIG_IEEE80211W */
};

#define RATETAB_ENT(_rate, _rateid, _flags) \
	{								\
		.bitrate	= (_rate),				\
		.hw_value	= (_rateid),				\
		.flags		= (_flags),				\
	}

#define CHAN2G(_channel, _freq, _flags) {			\
		.band			= NL80211_BAND_2GHZ,		\
		.center_freq		= (_freq),			\
		.hw_value		= (_channel),			\
		.flags			= (_flags),			\
		.max_antenna_gain	= 0,				\
		.max_power		= 0,				\
	}

#define CHAN5G(_channel, _flags) {				\
		.band			= NL80211_BAND_5GHZ,		\
		.center_freq		= 5000 + (5 * (_channel)),	\
		.hw_value		= (_channel),			\
		.flags			= (_flags),			\
		.max_antenna_gain	= 0,				\
		.max_power		= 0,				\
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
/* if wowlan is not supported, kernel generate a disconnect at each suspend
 * cf: /net/wireless/sysfs.c, so register a stub wowlan.
 * Moreover wowlan has to be enabled via a the nl80211_set_wowlan callback.
 * (from user space, e.g. iw phy0 wowlan enable)
 */
static const struct wiphy_wowlan_support wowlan_stub = {
	.flags = WIPHY_WOWLAN_ANY,
	.n_patterns = 0,
	.pattern_max_len = 0,
	.pattern_min_len = 0,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
	.max_pkt_offset = 0,
#endif
};
#endif

static struct ieee80211_rate rtw_rates[] = {
	RATETAB_ENT(10,  0x1,   0),
	RATETAB_ENT(20,  0x2,   0),
	RATETAB_ENT(55,  0x4,   0),
	RATETAB_ENT(110, 0x8,   0),
	RATETAB_ENT(60,  0x10,  0),
	RATETAB_ENT(90,  0x20,  0),
	RATETAB_ENT(120, 0x40,  0),
	RATETAB_ENT(180, 0x80,  0),
	RATETAB_ENT(240, 0x100, 0),
	RATETAB_ENT(360, 0x200, 0),
	RATETAB_ENT(480, 0x400, 0),
	RATETAB_ENT(540, 0x800, 0),
};

#define rtw_a_rates		(rtw_rates + 4)
#define RTW_A_RATES_NUM	8
#define rtw_g_rates		(rtw_rates + 0)
#define RTW_G_RATES_NUM	12

/* from center_ch_2g */
static struct ieee80211_channel rtw_2ghz_channels[MAX_CHANNEL_NUM_2G] = {
	CHAN2G(1, 2412, 0),
	CHAN2G(2, 2417, 0),
	CHAN2G(3, 2422, 0),
	CHAN2G(4, 2427, 0),
	CHAN2G(5, 2432, 0),
	CHAN2G(6, 2437, 0),
	CHAN2G(7, 2442, 0),
	CHAN2G(8, 2447, 0),
	CHAN2G(9, 2452, 0),
	CHAN2G(10, 2457, 0),
	CHAN2G(11, 2462, 0),
	CHAN2G(12, 2467, 0),
	CHAN2G(13, 2472, 0),
	CHAN2G(14, 2484, 0),
};

/* from center_ch_5g_20m */
static struct ieee80211_channel rtw_5ghz_a_channels[MAX_CHANNEL_NUM_5G] = {
	CHAN5G(36, 0),	CHAN5G(40, 0),	CHAN5G(44, 0),	CHAN5G(48, 0),

	CHAN5G(52, 0),	CHAN5G(56, 0),	CHAN5G(60, 0),	CHAN5G(64, 0),

	CHAN5G(100, 0),	CHAN5G(104, 0),	CHAN5G(108, 0),	CHAN5G(112, 0),
	CHAN5G(116, 0),	CHAN5G(120, 0),	CHAN5G(124, 0),	CHAN5G(128, 0),
	CHAN5G(132, 0),	CHAN5G(136, 0),	CHAN5G(140, 0),	CHAN5G(144, 0),

	CHAN5G(149, 0),	CHAN5G(153, 0),	CHAN5G(157, 0),	CHAN5G(161, 0),
	CHAN5G(165, 0),	CHAN5G(169, 0),	CHAN5G(173, 0),	CHAN5G(177, 0),
};

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0))
static u8 rtw_chbw_to_cfg80211_chan_def(struct wiphy *wiphy, struct cfg80211_chan_def *chdef, u8 ch, u8 bw, u8 offset, u8 ht)
{
	int freq, cfreq;
	struct ieee80211_channel *chan;
	u8 ret = _FAIL;

	_rtw_memset(chdef, 0, sizeof(*chdef));

	freq = rtw_ch2freq(ch);
	if (!freq)
		goto exit;

	cfreq = rtw_get_center_ch(ch, bw, offset);
	if (!cfreq)
		goto exit;
	cfreq = rtw_ch2freq(cfreq);
	if (!cfreq)
		goto exit;

	chan = ieee80211_get_channel(wiphy, freq);
	if (!chan)
		goto exit;

	if (bw == CHANNEL_WIDTH_20)
		chdef->width = ht ? NL80211_CHAN_WIDTH_20 : NL80211_CHAN_WIDTH_20_NOHT;
	else if (bw == CHANNEL_WIDTH_40)
		chdef->width = NL80211_CHAN_WIDTH_40;
	else if (bw == CHANNEL_WIDTH_80)
		chdef->width = NL80211_CHAN_WIDTH_80;
	else if (bw == CHANNEL_WIDTH_160)
		chdef->width = NL80211_CHAN_WIDTH_160;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0))
	else if (bw == CHANNEL_WIDTH_5)
		chdef->width = NL80211_CHAN_WIDTH_5;
	else if (bw == CHANNEL_WIDTH_10)
		chdef->width = NL80211_CHAN_WIDTH_10;
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)) */
	else {
		rtw_warn_on(1);
		goto exit;
	}

	chdef->chan = chan;
	chdef->center_freq1 = cfreq;

	ret = _SUCCESS;

exit:
	return ret;
}

#ifdef CONFIG_RTW_MESH
static const char *nl80211_chan_width_str(enum nl80211_chan_width cwidth)
{
	switch (cwidth) {
	case NL80211_CHAN_WIDTH_20_NOHT:
		return "20_NOHT";
	case NL80211_CHAN_WIDTH_20:
		return "20";
	case NL80211_CHAN_WIDTH_40:
		return "40";
	case NL80211_CHAN_WIDTH_80:
		return "80";
	case NL80211_CHAN_WIDTH_80P80:
		return "80+80";
	case NL80211_CHAN_WIDTH_160:
		return "160";
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0))
	case NL80211_CHAN_WIDTH_5:
		return "5";
	case NL80211_CHAN_WIDTH_10:
		return "10";
#endif
	default:
		return "INVALID";
	};
}

static void rtw_get_chbw_from_cfg80211_chan_def(struct cfg80211_chan_def *chdef, u8 *ht, u8 *ch, u8 *bw, u8 *offset)
{
	int pri_freq;
	struct ieee80211_channel *chan = chdef->chan;

	pri_freq = rtw_ch2freq(chan->hw_value);
	if (!pri_freq) {
		RTW_INFO("invalid channel:%d\n", chan->hw_value);
		rtw_warn_on(1);
		*ch = 0;
		return;
	}

	switch (chdef->width) {
	case NL80211_CHAN_WIDTH_20_NOHT:
		*ht = 0;
		*bw = CHANNEL_WIDTH_20;
		*offset = HAL_PRIME_CHNL_OFFSET_DONT_CARE;
		*ch = chan->hw_value;
		break;
	case NL80211_CHAN_WIDTH_20:
		*ht = 1;
		*bw = CHANNEL_WIDTH_20;
		*offset = HAL_PRIME_CHNL_OFFSET_DONT_CARE;
		*ch = chan->hw_value;
		break;
	case NL80211_CHAN_WIDTH_40:
		*ht = 1;
		*bw = CHANNEL_WIDTH_40;
		*offset = pri_freq > chdef->center_freq1 ? HAL_PRIME_CHNL_OFFSET_UPPER : HAL_PRIME_CHNL_OFFSET_LOWER;
		if (rtw_get_offset_by_chbw(chan->hw_value, *bw, offset))
			*ch = chan->hw_value;
		break;
	case NL80211_CHAN_WIDTH_80:
		*ht = 1;
		*bw = CHANNEL_WIDTH_80;
		if (rtw_get_offset_by_chbw(chan->hw_value, *bw, offset))
			*ch = chan->hw_value;
		break;
	case NL80211_CHAN_WIDTH_160:
		*ht = 1;
		*bw = CHANNEL_WIDTH_160;
		if (rtw_get_offset_by_chbw(chan->hw_value, *bw, offset))
			*ch = chan->hw_value;
		break;
	case NL80211_CHAN_WIDTH_80P80:
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0))
	case NL80211_CHAN_WIDTH_5:
	case NL80211_CHAN_WIDTH_10:
	#endif
	default:
		*ht = 0;
		*bw = CHANNEL_WIDTH_20;
		*offset = HAL_PRIME_CHNL_OFFSET_DONT_CARE;
		RTW_INFO("unsupported cwidth:%s\n", nl80211_chan_width_str(chdef->width));
		rtw_warn_on(1);
	};
}
#endif /* CONFIG_RTW_MESH */
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29))
static const char *nl80211_channel_type_str(enum nl80211_channel_type ctype)
{
	switch (ctype) {
	case NL80211_CHAN_NO_HT:
		return "NO_HT";
	case NL80211_CHAN_HT20:
		return "HT20";
	case NL80211_CHAN_HT40MINUS:
		return "HT40-";
	case NL80211_CHAN_HT40PLUS:
		return "HT40+";
	default:
		return "INVALID";
	};
}

static enum nl80211_channel_type rtw_chbw_to_nl80211_channel_type(u8 ch, u8 bw, u8 offset, u8 ht)
{
	rtw_warn_on(!ht && (bw >= CHANNEL_WIDTH_40 || offset != HAL_PRIME_CHNL_OFFSET_DONT_CARE));

	if (!ht)
		return NL80211_CHAN_NO_HT;
	if (bw >= CHANNEL_WIDTH_40) {
		if (offset == HAL_PRIME_CHNL_OFFSET_UPPER)
			return NL80211_CHAN_HT40MINUS;
		else if (offset == HAL_PRIME_CHNL_OFFSET_LOWER)
			return NL80211_CHAN_HT40PLUS;
		else
			rtw_warn_on(1);
	}
	return NL80211_CHAN_HT20;
}

static void rtw_get_chbw_from_nl80211_channel_type(struct ieee80211_channel *chan, enum nl80211_channel_type ctype, u8 *ht, u8 *ch, u8 *bw, u8 *offset)
{
	int pri_freq;

	pri_freq = rtw_ch2freq(chan->hw_value);
	if (!pri_freq) {
		RTW_INFO("invalid channel:%d\n", chan->hw_value);
		rtw_warn_on(1);
		*ch = 0;
		return;
	}
	*ch = chan->hw_value;

	switch (ctype) {
	case NL80211_CHAN_NO_HT:
		*ht = 0;
		*bw = CHANNEL_WIDTH_20;
		*offset = HAL_PRIME_CHNL_OFFSET_DONT_CARE;
		break;
	case NL80211_CHAN_HT20:
		*ht = 1;
		*bw = CHANNEL_WIDTH_20;
		*offset = HAL_PRIME_CHNL_OFFSET_DONT_CARE;
		break;
	case NL80211_CHAN_HT40MINUS:
		*ht = 1;
		*bw = CHANNEL_WIDTH_40;
		*offset = HAL_PRIME_CHNL_OFFSET_UPPER;
		break;
	case NL80211_CHAN_HT40PLUS:
		*ht = 1;
		*bw = CHANNEL_WIDTH_40;
		*offset = HAL_PRIME_CHNL_OFFSET_LOWER;
		break;
	default:
		*ht = 0;
		*bw = CHANNEL_WIDTH_20;
		*offset = HAL_PRIME_CHNL_OFFSET_DONT_CARE;
		RTW_INFO("unsupported ctype:%s\n", nl80211_channel_type_str(ctype));
		rtw_warn_on(1);
	};
}
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)) */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0))
bool rtw_cfg80211_allow_ch_switch_notify(_adapter *adapter)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0))
	if ((!MLME_IS_AP(adapter))
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0))
		&& (!MLME_IS_ADHOC(adapter))
		&& (!MLME_IS_ADHOC_MASTER(adapter))
		&& (!MLME_IS_MESH(adapter))
#elif defined(CONFIG_RTW_MESH)
		&& (!MLME_IS_MESH(adapter))
#endif
		)
		return 0;
#endif
	return 1;
}

u8 rtw_cfg80211_ch_switch_notify(_adapter *adapter, u8 ch, u8 bw, u8 offset,
	u8 ht, bool started)
{
	struct wiphy *wiphy = adapter_to_wiphy(adapter);
	u8 ret = _SUCCESS;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0))
	struct cfg80211_chan_def chdef = {};

	ret = rtw_chbw_to_cfg80211_chan_def(wiphy, &chdef, ch, bw, offset, ht);
	if (ret != _SUCCESS)
		goto exit;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0))
	if (started) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0))

		/* --- cfg80211_ch_switch_started_notfiy() ---
		 *  A new parameter, bool quiet, is added from Linux kernel v5.11,
		 *  to see if block-tx was requested by the AP. since currently,
		 *  the API is used for station before connected in rtw_chk_start_clnt_join()
		 *  the quiet is set to false here first. May need to refine it if
		 *  called by others with block-tx.
		 */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0))
		cfg80211_ch_switch_started_notify(adapter->pnetdev, &chdef, 0, 0, false, 0);
#else
		cfg80211_ch_switch_started_notify(adapter->pnetdev, &chdef, 0, 0, 0, false);
#endif
#else
		cfg80211_ch_switch_started_notify(adapter->pnetdev, &chdef, 0, false);
#endif
#else
		cfg80211_ch_switch_started_notify(adapter->pnetdev, &chdef, 0);
#endif
		goto exit;
	}
#endif

	if (!rtw_cfg80211_allow_ch_switch_notify(adapter))
		goto exit;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 2))
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0))
	cfg80211_ch_switch_notify(adapter->pnetdev, &chdef, 0, 0);
#else
	cfg80211_ch_switch_notify(adapter->pnetdev, &chdef, 0, 0);
#endif
#else
	cfg80211_ch_switch_notify(adapter->pnetdev, &chdef);
#endif

#else
	int freq = rtw_ch2freq(ch);
	enum nl80211_channel_type ctype;

	if (!rtw_cfg80211_allow_ch_switch_notify(adapter))
		goto exit;

	if (!freq) {
		ret = _FAIL;
		goto exit;
	}

	ctype = rtw_chbw_to_nl80211_channel_type(ch, bw, offset, ht);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 2))
	cfg80211_ch_switch_notify(adapter->pnetdev, freq, ctype, 0);
#else
	cfg80211_ch_switch_notify(adapter->pnetdev, freq, ctype);
#endif
#endif

exit:
	return ret;
}
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)) */

void rtw_2g_channels_init(struct ieee80211_channel *channels)
{
	_rtw_memcpy((void *)channels, (void *)rtw_2ghz_channels, sizeof(rtw_2ghz_channels));
}

void rtw_5g_channels_init(struct ieee80211_channel *channels)
{
	_rtw_memcpy((void *)channels, (void *)rtw_5ghz_a_channels, sizeof(rtw_5ghz_a_channels));
}

void rtw_2g_rates_init(struct ieee80211_rate *rates)
{
	_rtw_memcpy(rates, rtw_g_rates,
		sizeof(struct ieee80211_rate) * RTW_G_RATES_NUM
	);
}

void rtw_5g_rates_init(struct ieee80211_rate *rates)
{
	_rtw_memcpy(rates, rtw_a_rates,
		sizeof(struct ieee80211_rate) * RTW_A_RATES_NUM
	);
}

struct ieee80211_supported_band *rtw_spt_band_alloc(BAND_TYPE band)
{
	struct ieee80211_supported_band *spt_band = NULL;
	int n_channels, n_bitrates;

	if (band == BAND_ON_2_4G) {
		n_channels = MAX_CHANNEL_NUM_2G;
		n_bitrates = RTW_G_RATES_NUM;
	} else if (band == BAND_ON_5G) {
		n_channels = MAX_CHANNEL_NUM_5G;
		n_bitrates = RTW_A_RATES_NUM;
	} else
		goto exit;

	spt_band = (struct ieee80211_supported_band *)rtw_zmalloc(
		sizeof(struct ieee80211_supported_band)
		+ sizeof(struct ieee80211_channel) * n_channels
		+ sizeof(struct ieee80211_rate) * n_bitrates
	);
	if (!spt_band)
		goto exit;

	spt_band->channels = (struct ieee80211_channel *)(((u8 *)spt_band) + sizeof(struct ieee80211_supported_band));
	spt_band->bitrates = (struct ieee80211_rate *)(((u8 *)spt_band->channels) + sizeof(struct ieee80211_channel) * n_channels);
	spt_band->band = rtw_band_to_nl80211_band(band);
	spt_band->n_channels = n_channels;
	spt_band->n_bitrates = n_bitrates;

exit:
	return spt_band;
}

void rtw_spt_band_free(struct ieee80211_supported_band *spt_band)
{
	u32 size = 0;

	if (!spt_band)
		return;

	if (spt_band->band == NL80211_BAND_2GHZ) {
		size = sizeof(struct ieee80211_supported_band)
			+ sizeof(struct ieee80211_channel) * MAX_CHANNEL_NUM_2G
			+ sizeof(struct ieee80211_rate) * RTW_G_RATES_NUM;
	} else if (spt_band->band == NL80211_BAND_5GHZ) {
		size = sizeof(struct ieee80211_supported_band)
			+ sizeof(struct ieee80211_channel) * MAX_CHANNEL_NUM_5G
			+ sizeof(struct ieee80211_rate) * RTW_A_RATES_NUM;
	} else {

	}
	rtw_mfree((u8 *)spt_band, size);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE)
static const struct ieee80211_txrx_stypes
	rtw_cfg80211_default_mgmt_stypes[NUM_NL80211_IFTYPES] = {
	[NL80211_IFTYPE_ADHOC] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ACTION >> 4)
	},
	[NL80211_IFTYPE_STATION] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
		BIT(IEEE80211_STYPE_AUTH >> 4) |
		BIT(IEEE80211_STYPE_PROBE_REQ >> 4)
	},
	[NL80211_IFTYPE_AP] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
		BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
		BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
		BIT(IEEE80211_STYPE_DISASSOC >> 4) |
		BIT(IEEE80211_STYPE_AUTH >> 4) |
		BIT(IEEE80211_STYPE_DEAUTH >> 4) |
		BIT(IEEE80211_STYPE_ACTION >> 4)
	},
	[NL80211_IFTYPE_AP_VLAN] = {
		/* copy AP */
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
		BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
		BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
		BIT(IEEE80211_STYPE_DISASSOC >> 4) |
		BIT(IEEE80211_STYPE_AUTH >> 4) |
		BIT(IEEE80211_STYPE_DEAUTH >> 4) |
		BIT(IEEE80211_STYPE_ACTION >> 4)
	},
	[NL80211_IFTYPE_P2P_CLIENT] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
		BIT(IEEE80211_STYPE_PROBE_REQ >> 4)
	},
	[NL80211_IFTYPE_P2P_GO] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
		BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
		BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
		BIT(IEEE80211_STYPE_DISASSOC >> 4) |
		BIT(IEEE80211_STYPE_AUTH >> 4) |
		BIT(IEEE80211_STYPE_DEAUTH >> 4) |
		BIT(IEEE80211_STYPE_ACTION >> 4)
	},
#if defined(RTW_DEDICATED_P2P_DEVICE)
	[NL80211_IFTYPE_P2P_DEVICE] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
			BIT(IEEE80211_STYPE_PROBE_REQ >> 4)
	},
#endif
#if defined(CONFIG_RTW_MESH)
	[NL80211_IFTYPE_MESH_POINT] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ACTION >> 4)
			| BIT(IEEE80211_STYPE_AUTH >> 4)
	},
#endif

};
#endif

NDIS_802_11_NETWORK_INFRASTRUCTURE nl80211_iftype_to_rtw_network_type(enum nl80211_iftype type)
{
	switch (type) {
	case NL80211_IFTYPE_ADHOC:
		return Ndis802_11IBSS;

	#if defined(CONFIG_P2P) && ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE))
	case NL80211_IFTYPE_P2P_CLIENT:
	#endif
	case NL80211_IFTYPE_STATION:
		return Ndis802_11Infrastructure;

#ifdef CONFIG_AP_MODE
	#if defined(CONFIG_P2P) && ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE))
	case NL80211_IFTYPE_P2P_GO:
	#endif
	case NL80211_IFTYPE_AP:
		return Ndis802_11APMode;
#endif

#ifdef CONFIG_RTW_MESH
	case NL80211_IFTYPE_MESH_POINT:
		return Ndis802_11_mesh;
#endif

#ifdef CONFIG_WIFI_MONITOR
	case NL80211_IFTYPE_MONITOR:
		return Ndis802_11Monitor;
#endif /* CONFIG_WIFI_MONITOR */

	default:
		return Ndis802_11InfrastructureMax;
	}
}

u32 nl80211_iftype_to_rtw_mlme_state(enum nl80211_iftype type)
{
	switch (type) {
	case NL80211_IFTYPE_ADHOC:
		return WIFI_ADHOC_STATE;

	#if defined(CONFIG_P2P) && ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE))
	case NL80211_IFTYPE_P2P_CLIENT:
	#endif
	case NL80211_IFTYPE_STATION:
		return WIFI_STATION_STATE;

#ifdef CONFIG_AP_MODE
	#if defined(CONFIG_P2P) && ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE))
	case NL80211_IFTYPE_P2P_GO:
	#endif
	case NL80211_IFTYPE_AP:
		return WIFI_AP_STATE;
#endif

#ifdef CONFIG_RTW_MESH
	case NL80211_IFTYPE_MESH_POINT:
		return WIFI_MESH_STATE;
#endif

	case NL80211_IFTYPE_MONITOR:
		return WIFI_MONITOR_STATE;

	default:
		return WIFI_NULL_STATE;
	}
}

static int rtw_cfg80211_sync_iftype(_adapter *adapter)
{
	struct wireless_dev *rtw_wdev = adapter->rtw_wdev;

	if (!(nl80211_iftype_to_rtw_mlme_state(rtw_wdev->iftype) & MLME_STATE(adapter))) {
		/* iftype and mlme state is not syc */
		NDIS_802_11_NETWORK_INFRASTRUCTURE network_type;

		network_type = nl80211_iftype_to_rtw_network_type(rtw_wdev->iftype);
		if (network_type != Ndis802_11InfrastructureMax) {
			if (rtw_pwr_wakeup(adapter) == _FAIL) {
				RTW_WARN(FUNC_ADPT_FMT" call rtw_pwr_wakeup fail\n", FUNC_ADPT_ARG(adapter));
				return _FAIL;
			}

			rtw_set_802_11_infrastructure_mode(adapter, network_type, 0);
			rtw_setopmode_cmd(adapter, network_type, RTW_CMDF_WAIT_ACK);
		} else {
			rtw_warn_on(1);
			RTW_WARN(FUNC_ADPT_FMT" iftype:%u is not support\n", FUNC_ADPT_ARG(adapter), rtw_wdev->iftype);
			return _FAIL;
		}
	}

	return _SUCCESS;
}

static u64 rtw_get_systime_us(void)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
	return ktime_to_us(ktime_get_boottime());
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39))
	struct timespec ts;
	get_monotonic_boottime(&ts);
	return ((u64)ts.tv_sec * 1000000) + ts.tv_nsec / 1000;
#else
	struct timeval tv;
	do_gettimeofday(&tv);
	return ((u64)tv.tv_sec * 1000000) + tv.tv_usec;
#endif
}

/* Try to remove non target BSS's SR to reduce PBC overlap rate */
static int rtw_cfg80211_clear_wps_sr_of_non_target_bss(_adapter *padapter, struct wlan_network *pnetwork, struct cfg80211_ssid *req_ssid)
{
	int ret = 0;
	u8 *psr = NULL, sr = 0;
	NDIS_802_11_SSID *pssid = &pnetwork->network.Ssid;
	u32 wpsielen = 0;
	u8 *wpsie = NULL;

	if (pssid->SsidLength == req_ssid->ssid_len
		&& _rtw_memcmp(pssid->Ssid, req_ssid->ssid, req_ssid->ssid_len) == _TRUE)
		goto exit;

	wpsie = rtw_get_wps_ie(pnetwork->network.IEs + _FIXED_IE_LENGTH_
		, pnetwork->network.IELength - _FIXED_IE_LENGTH_, NULL, &wpsielen);
	if (wpsie && wpsielen > 0)
		psr = rtw_get_wps_attr_content(wpsie, wpsielen, WPS_ATTR_SELECTED_REGISTRAR, &sr, NULL);

	if (psr && sr) {
		if (0)
			RTW_INFO("clear sr of non target bss:%s("MAC_FMT")\n"
				, pssid->Ssid, MAC_ARG(pnetwork->network.MacAddress));
		*psr = 0; /* clear sr */
		ret = 1;
	}

exit:
	return ret;
}

#define MAX_BSSINFO_LEN 1000
struct cfg80211_bss *rtw_cfg80211_inform_bss(_adapter *padapter, struct wlan_network *pnetwork)
{
	struct ieee80211_channel *notify_channel;
	struct cfg80211_bss *bss = NULL;
	/* struct ieee80211_supported_band *band;       */
	u16 channel;
	u32 freq;
	u64 notify_timestamp;
	u16 notify_capability;
	u16 notify_interval;
	u8 *notify_ie;
	size_t notify_ielen;
	s32 notify_signal;
	/* u8 buf[MAX_BSSINFO_LEN]; */

	u8 *pbuf;
	size_t buf_size = MAX_BSSINFO_LEN;
	size_t len, bssinf_len = 0;
	struct rtw_ieee80211_hdr *pwlanhdr;
	unsigned short *fctrl;
	u8	bc_addr[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	struct wireless_dev *wdev = padapter->rtw_wdev;
	struct wiphy *wiphy = wdev->wiphy;
	struct mlme_priv *pmlmepriv = &(padapter->mlmepriv);

	pbuf = rtw_zmalloc(buf_size);
	if (pbuf == NULL) {
		RTW_INFO("%s pbuf allocate failed  !!\n", __FUNCTION__);
		return bss;
	}

	/* RTW_INFO("%s\n", __func__); */

	bssinf_len = pnetwork->network.IELength + sizeof(struct rtw_ieee80211_hdr_3addr);
	if (bssinf_len > buf_size) {
		RTW_INFO("%s IE Length too long > %zu byte\n", __FUNCTION__, buf_size);
		goto exit;
	}

#ifndef CONFIG_WAPI_SUPPORT
	{
		u16 wapi_len = 0;

		if (rtw_get_wapi_ie(pnetwork->network.IEs, pnetwork->network.IELength, NULL, &wapi_len) > 0) {
			if (wapi_len > 0) {
				RTW_INFO("%s, no support wapi!\n", __FUNCTION__);
				goto exit;
			}
		}
	}
#endif /* !CONFIG_WAPI_SUPPORT */

	channel = pnetwork->network.Configuration.DSConfig;
	freq = rtw_ch2freq(channel);
	notify_channel = ieee80211_get_channel(wiphy, freq);

	if (0)
		notify_timestamp = le64_to_cpu(*(u64 *)rtw_get_timestampe_from_ie(pnetwork->network.IEs));
	else
		notify_timestamp = rtw_get_systime_us();

	notify_interval = le16_to_cpu(*(u16 *)rtw_get_beacon_interval_from_ie(pnetwork->network.IEs));
	notify_capability = le16_to_cpu(*(u16 *)rtw_get_capability_from_ie(pnetwork->network.IEs));

	notify_ie = pnetwork->network.IEs + _FIXED_IE_LENGTH_;
	notify_ielen = pnetwork->network.IELength - _FIXED_IE_LENGTH_;

	/* We've set wiphy's signal_type as CFG80211_SIGNAL_TYPE_MBM: signal strength in mBm (100*dBm) */
	if (check_fwstate(pmlmepriv, WIFI_ASOC_STATE) == _TRUE &&
		is_same_network(&pmlmepriv->cur_network.network, &pnetwork->network, 0)) {
		notify_signal = 100 * translate_percentage_to_dbm(padapter->recvpriv.signal_strength); /* dbm */
	} else {
		notify_signal = 100 * translate_percentage_to_dbm(pnetwork->network.PhyInfo.SignalStrength); /* dbm */
	}

#if 0
	RTW_INFO("bssid: "MAC_FMT"\n", MAC_ARG(pnetwork->network.MacAddress));
	RTW_INFO("Channel: %d(%d)\n", channel, freq);
	RTW_INFO("Capability: %X\n", notify_capability);
	RTW_INFO("Beacon interval: %d\n", notify_interval);
	RTW_INFO("Signal: %d\n", notify_signal);
	RTW_INFO("notify_timestamp: %llu\n", notify_timestamp);
#endif

	/* pbuf = buf; */

	pwlanhdr = (struct rtw_ieee80211_hdr *)pbuf;
	fctrl = &(pwlanhdr->frame_ctl);
	*(fctrl) = 0;

	SetSeqNum(pwlanhdr, 0/*pmlmeext->mgnt_seq*/);
	/* pmlmeext->mgnt_seq++; */

	if (pnetwork->network.Reserved[0] == BSS_TYPE_BCN) { /* WIFI_BEACON */
		_rtw_memcpy(pwlanhdr->addr1, bc_addr, ETH_ALEN);
		set_frame_sub_type(pbuf, WIFI_BEACON);
	} else {
		_rtw_memcpy(pwlanhdr->addr1, adapter_mac_addr(padapter), ETH_ALEN);
		set_frame_sub_type(pbuf, WIFI_PROBERSP);
	}

	_rtw_memcpy(pwlanhdr->addr2, pnetwork->network.MacAddress, ETH_ALEN);
	_rtw_memcpy(pwlanhdr->addr3, pnetwork->network.MacAddress, ETH_ALEN);


	/* pbuf += sizeof(struct rtw_ieee80211_hdr_3addr); */
	len = sizeof(struct rtw_ieee80211_hdr_3addr);
	_rtw_memcpy((pbuf + len), pnetwork->network.IEs, pnetwork->network.IELength);
	*((u64 *)(pbuf + len)) = cpu_to_le64(notify_timestamp);

	len += pnetwork->network.IELength;

	#if defined(CONFIG_P2P) && 0
	if(rtw_get_p2p_ie(pnetwork->network.IEs+12, pnetwork->network.IELength-12, NULL, NULL))
		RTW_INFO("%s, got p2p_ie\n", __func__);
	#endif

#if 1
	bss = cfg80211_inform_bss_frame(wiphy, notify_channel, (struct ieee80211_mgmt *)pbuf,
					len, notify_signal, GFP_ATOMIC);
#else

	bss = cfg80211_inform_bss(wiphy, notify_channel, (const u8 *)pnetwork->network.MacAddress,
		notify_timestamp, notify_capability, notify_interval, notify_ie,
		notify_ielen, notify_signal, GFP_ATOMIC/*GFP_KERNEL*/);
#endif

	if (unlikely(!bss)) {
		RTW_INFO(FUNC_ADPT_FMT" bss NULL\n", FUNC_ADPT_ARG(padapter));
		goto exit;
	}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38))
#ifndef COMPAT_KERNEL_RELEASE
	/* patch for cfg80211, update beacon ies to information_elements */
	if (pnetwork->network.Reserved[0] == BSS_TYPE_BCN) { /* WIFI_BEACON */

		if (bss->len_information_elements != bss->len_beacon_ies) {
			bss->information_elements = bss->beacon_ies;
			bss->len_information_elements =  bss->len_beacon_ies;
		}
	}
#endif /* COMPAT_KERNEL_RELEASE */
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38) */

#if 0
	{
		if (bss->information_elements == bss->proberesp_ies) {
			if (bss->len_information_elements !=  bss->len_proberesp_ies)
				RTW_INFO("error!, len_information_elements != bss->len_proberesp_ies\n");
		} else if (bss->len_information_elements <  bss->len_beacon_ies) {
			bss->information_elements = bss->beacon_ies;
			bss->len_information_elements =  bss->len_beacon_ies;
		}
	}
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	cfg80211_put_bss(wiphy, bss);
#else
	cfg80211_put_bss(bss);
#endif

exit:
	if (pbuf)
		rtw_mfree(pbuf, buf_size);
	return bss;

}

/*
	Check the given bss is valid by kernel API cfg80211_get_bss()
	@padapter : the given adapter

	return _TRUE if bss is valid,  _FALSE for not found.
*/
int rtw_cfg80211_check_bss(_adapter *padapter)
{
	WLAN_BSSID_EX  *pnetwork = &(padapter->mlmeextpriv.mlmext_info.network);
	struct cfg80211_bss *bss = NULL;
	struct ieee80211_channel *notify_channel = NULL;
	u32 freq;

	if (!(pnetwork) || !(padapter->rtw_wdev))
		return _FALSE;

	freq = rtw_ch2freq(pnetwork->Configuration.DSConfig);
	notify_channel = ieee80211_get_channel(padapter->rtw_wdev->wiphy, freq);
	bss = cfg80211_get_bss(padapter->rtw_wdev->wiphy, notify_channel,
			pnetwork->MacAddress, pnetwork->Ssid.Ssid,
			pnetwork->Ssid.SsidLength,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
			pnetwork->InfrastructureMode == Ndis802_11Infrastructure?IEEE80211_BSS_TYPE_ESS:IEEE80211_BSS_TYPE_IBSS,
			IEEE80211_PRIVACY(pnetwork->Privacy));
#else
			pnetwork->InfrastructureMode == Ndis802_11Infrastructure?WLAN_CAPABILITY_ESS:WLAN_CAPABILITY_IBSS, pnetwork->InfrastructureMode == Ndis802_11Infrastructure?WLAN_CAPABILITY_ESS:WLAN_CAPABILITY_IBSS);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	cfg80211_put_bss(padapter->rtw_wdev->wiphy, bss);
#else
	cfg80211_put_bss(bss);
#endif

	return bss != NULL;
}

void rtw_cfg80211_ibss_indicate_connect(_adapter *padapter)
{
	struct mlme_priv *pmlmepriv = &padapter->mlmepriv;
	struct wlan_network  *cur_network = &(pmlmepriv->cur_network);
	struct wireless_dev *pwdev = padapter->rtw_wdev;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0))
	struct wiphy *wiphy = pwdev->wiphy;
	int freq = 2412;
	struct ieee80211_channel *notify_channel;
#endif

	RTW_INFO(FUNC_ADPT_FMT"\n", FUNC_ADPT_ARG(padapter));

	if (pwdev->iftype != NL80211_IFTYPE_ADHOC)
		return;

	if (!rtw_cfg80211_check_bss(padapter)) {
		WLAN_BSSID_EX  *pnetwork = &(padapter->mlmeextpriv.mlmext_info.network);
		struct wlan_network *scanned = pmlmepriv->cur_network_scanned;

		if (check_fwstate(pmlmepriv, WIFI_ADHOC_MASTER_STATE) == _TRUE) {

			_rtw_memcpy(&cur_network->network, pnetwork, sizeof(WLAN_BSSID_EX));
			if (cur_network) {
				if (!rtw_cfg80211_inform_bss(padapter, cur_network))
					RTW_INFO(FUNC_ADPT_FMT" inform fail !!\n", FUNC_ADPT_ARG(padapter));
				else
					RTW_INFO(FUNC_ADPT_FMT" inform success !!\n", FUNC_ADPT_ARG(padapter));
			} else {
				RTW_INFO("cur_network is not exist!!!\n");
				return ;
			}
		} else {
			if (scanned == NULL)
				rtw_warn_on(1);

			if (_rtw_memcmp(&(scanned->network.Ssid), &(pnetwork->Ssid), sizeof(NDIS_802_11_SSID)) == _TRUE
				&& _rtw_memcmp(scanned->network.MacAddress, pnetwork->MacAddress, sizeof(NDIS_802_11_MAC_ADDRESS)) == _TRUE
			) {
				if (!rtw_cfg80211_inform_bss(padapter, scanned))
					RTW_INFO(FUNC_ADPT_FMT" inform fail !!\n", FUNC_ADPT_ARG(padapter));
				else {
					/* RTW_INFO(FUNC_ADPT_FMT" inform success !!\n", FUNC_ADPT_ARG(padapter)); */
				}
			} else {
				RTW_INFO("scanned & pnetwork compare fail\n");
				rtw_warn_on(1);
			}
		}

		if (!rtw_cfg80211_check_bss(padapter))
			RTW_PRINT(FUNC_ADPT_FMT" BSS not found !!\n", FUNC_ADPT_ARG(padapter));
	}
	/* notify cfg80211 that device joined an IBSS */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0))
	freq = rtw_ch2freq(cur_network->network.Configuration.DSConfig);
	if (1)
		RTW_INFO("chan: %d, freq: %d\n", cur_network->network.Configuration.DSConfig, freq);
	notify_channel = ieee80211_get_channel(wiphy, freq);
	cfg80211_ibss_joined(padapter->pnetdev, cur_network->network.MacAddress, notify_channel, GFP_ATOMIC);
#else
	cfg80211_ibss_joined(padapter->pnetdev, cur_network->network.MacAddress, GFP_ATOMIC);
#endif
}

void rtw_cfg80211_indicate_connect(_adapter *padapter)
{
	struct mlme_priv *pmlmepriv = &padapter->mlmepriv;
	struct wlan_network  *cur_network = &(pmlmepriv->cur_network);
	struct wireless_dev *pwdev = padapter->rtw_wdev;
	struct rtw_wdev_priv *pwdev_priv = adapter_wdev_data(padapter);
	_irqL irqL;
#ifdef CONFIG_P2P
	struct wifidirect_info *pwdinfo = &(padapter->wdinfo);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	struct cfg80211_roam_info roam_info ={};
#endif

	RTW_INFO(FUNC_ADPT_FMT"\n", FUNC_ADPT_ARG(padapter));
	if (pwdev->iftype != NL80211_IFTYPE_STATION
		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE)
		&& pwdev->iftype != NL80211_IFTYPE_P2P_CLIENT
		#endif
	)
		return;

	if (!MLME_IS_STA(padapter))
		return;

#ifdef CONFIG_P2P
	if (pwdinfo->driver_interface == DRIVER_CFG80211) {
		#if !RTW_P2P_GROUP_INTERFACE
		if (!rtw_p2p_chk_state(pwdinfo, P2P_STATE_NONE)) {
			rtw_p2p_set_pre_state(pwdinfo, rtw_p2p_state(pwdinfo));
			rtw_p2p_set_role(pwdinfo, P2P_ROLE_CLIENT);
			rtw_p2p_set_state(pwdinfo, P2P_STATE_GONEGO_OK);
			RTW_INFO("%s, role=%d, p2p_state=%d, pre_p2p_state=%d\n", __func__, rtw_p2p_role(pwdinfo), rtw_p2p_state(pwdinfo), rtw_p2p_pre_state(pwdinfo));
		}
		#endif
	}
#endif /* CONFIG_P2P */

	if (check_fwstate(pmlmepriv, WIFI_MONITOR_STATE) != _TRUE) {
		WLAN_BSSID_EX  *pnetwork = &(padapter->mlmeextpriv.mlmext_info.network);
		struct wlan_network *scanned = pmlmepriv->cur_network_scanned;

		/* RTW_INFO(FUNC_ADPT_FMT" BSS not found\n", FUNC_ADPT_ARG(padapter)); */

		if (scanned == NULL) {
			rtw_warn_on(1);
			goto check_bss;
		}

		if (_rtw_memcmp(scanned->network.MacAddress, pnetwork->MacAddress, sizeof(NDIS_802_11_MAC_ADDRESS)) == _TRUE
			&& _rtw_memcmp(&(scanned->network.Ssid), &(pnetwork->Ssid), sizeof(NDIS_802_11_SSID)) == _TRUE
		) {
			if (!rtw_cfg80211_inform_bss(padapter, scanned))
				RTW_INFO(FUNC_ADPT_FMT" inform fail !!\n", FUNC_ADPT_ARG(padapter));
			else {
				/* RTW_INFO(FUNC_ADPT_FMT" inform success !!\n", FUNC_ADPT_ARG(padapter)); */
			}
		} else {
			RTW_INFO("scanned: %s("MAC_FMT"), cur: %s("MAC_FMT")\n",
				scanned->network.Ssid.Ssid, MAC_ARG(scanned->network.MacAddress),
				pnetwork->Ssid.Ssid, MAC_ARG(pnetwork->MacAddress)
			);
			rtw_warn_on(1);
		}
	}

check_bss:
	if (!rtw_cfg80211_check_bss(padapter))
		RTW_PRINT(FUNC_ADPT_FMT" BSS not found !!\n", FUNC_ADPT_ARG(padapter));

	_enter_critical_bh(&pwdev_priv->connect_req_lock, &irqL);

	if (rtw_to_roam(padapter) > 0) {
		#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 39) || defined(COMPAT_KERNEL_RELEASE)
		struct wiphy *wiphy = pwdev->wiphy;
		struct ieee80211_channel *notify_channel;
		u32 freq;
		u16 channel = cur_network->network.Configuration.DSConfig;

		freq = rtw_ch2freq(channel);
		notify_channel = ieee80211_get_channel(wiphy, freq);
		#endif

		#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0))
		roam_info.links[0].bssid = cur_network->network.MacAddress;
#else
		roam_info.bssid = cur_network->network.MacAddress;
#endif
		roam_info.req_ie = pmlmepriv->assoc_req + sizeof(struct rtw_ieee80211_hdr_3addr) + 2;
		roam_info.req_ie_len = pmlmepriv->assoc_req_len - sizeof(struct rtw_ieee80211_hdr_3addr) - 2;
		roam_info.resp_ie = pmlmepriv->assoc_rsp + sizeof(struct rtw_ieee80211_hdr_3addr) + 6;
		roam_info.resp_ie_len = pmlmepriv->assoc_rsp_len - sizeof(struct rtw_ieee80211_hdr_3addr) - 6;

		cfg80211_roamed(padapter->pnetdev, &roam_info, GFP_ATOMIC);
		#else
		cfg80211_roamed(padapter->pnetdev
			#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 39) || defined(COMPAT_KERNEL_RELEASE)
			, notify_channel
			#endif
			, cur_network->network.MacAddress
			, pmlmepriv->assoc_req + sizeof(struct rtw_ieee80211_hdr_3addr) + 2
			, pmlmepriv->assoc_req_len - sizeof(struct rtw_ieee80211_hdr_3addr) - 2
			, pmlmepriv->assoc_rsp + sizeof(struct rtw_ieee80211_hdr_3addr) + 6
			, pmlmepriv->assoc_rsp_len - sizeof(struct rtw_ieee80211_hdr_3addr) - 6
			, GFP_ATOMIC);
		#endif /*LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)*/

		RTW_INFO(FUNC_ADPT_FMT" call cfg80211_roamed\n", FUNC_ADPT_ARG(padapter));

#ifdef CONFIG_RTW_80211R
		if (rtw_ft_roam(padapter))
			rtw_ft_set_status(padapter, RTW_FT_ASSOCIATED_STA);
#endif
	} else {
		#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0) || defined(COMPAT_KERNEL_RELEASE)
		RTW_INFO("pwdev->sme_state(b)=%d\n", pwdev->sme_state);
		#endif

		if (check_fwstate(pmlmepriv, WIFI_MONITOR_STATE) != _TRUE)
			rtw_cfg80211_connect_result(pwdev, cur_network->network.MacAddress
				, pmlmepriv->assoc_req + sizeof(struct rtw_ieee80211_hdr_3addr) + 2
				, pmlmepriv->assoc_req_len - sizeof(struct rtw_ieee80211_hdr_3addr) - 2
				, pmlmepriv->assoc_rsp + sizeof(struct rtw_ieee80211_hdr_3addr) + 6
				, pmlmepriv->assoc_rsp_len - sizeof(struct rtw_ieee80211_hdr_3addr) - 6
				, WLAN_STATUS_SUCCESS, GFP_ATOMIC);
		#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0) || defined(COMPAT_KERNEL_RELEASE)
		RTW_INFO("pwdev->sme_state(a)=%d\n", pwdev->sme_state);
		#endif
	}

	rtw_wdev_free_connect_req(pwdev_priv);

	_exit_critical_bh(&pwdev_priv->connect_req_lock, &irqL);
}

void rtw_cfg80211_indicate_disconnect(_adapter *padapter, u16 reason, u8 locally_generated)
{
	struct wireless_dev *pwdev = padapter->rtw_wdev;
	struct rtw_wdev_priv *pwdev_priv = adapter_wdev_data(padapter);
	_irqL irqL;
#ifdef CONFIG_P2P
	struct wifidirect_info *pwdinfo = &(padapter->wdinfo);
#endif

	RTW_INFO(FUNC_ADPT_FMT" ,reason = %d\n", FUNC_ADPT_ARG(padapter), reason);

	/*always replace privated definitions with wifi reserved value 0*/
	if (WLAN_REASON_IS_PRIVATE(reason))
		reason = 0;

	if (pwdev->iftype != NL80211_IFTYPE_STATION
		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE)
		&& pwdev->iftype != NL80211_IFTYPE_P2P_CLIENT
		#endif
	)
		return;

	if (!MLME_IS_STA(padapter))
		return;

#ifdef CONFIG_P2P
	if (pwdinfo->driver_interface == DRIVER_CFG80211) {
		if (!rtw_p2p_chk_state(pwdinfo, P2P_STATE_NONE)) {
			rtw_p2p_set_state(pwdinfo, rtw_p2p_pre_state(pwdinfo));

			#if RTW_P2P_GROUP_INTERFACE
			#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE)
			if (pwdev->iftype != NL80211_IFTYPE_P2P_CLIENT)
			#endif
			#endif
				rtw_p2p_set_role(pwdinfo, P2P_ROLE_DEVICE);

			RTW_INFO("%s, role=%d, p2p_state=%d, pre_p2p_state=%d\n", __func__, rtw_p2p_role(pwdinfo), rtw_p2p_state(pwdinfo), rtw_p2p_pre_state(pwdinfo));
		}
	}
#endif /* CONFIG_P2P */

	_enter_critical_bh(&pwdev_priv->connect_req_lock, &irqL);

	if (padapter->ndev_unregistering || !rtw_wdev_not_indic_disco(pwdev_priv)) {
		#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0) || defined(COMPAT_KERNEL_RELEASE)
		RTW_INFO("pwdev->sme_state(b)=%d\n", pwdev->sme_state);

		if (pwdev->sme_state == CFG80211_SME_CONNECTING) {
			RTW_INFO(FUNC_ADPT_FMT" call cfg80211_connect_result, reason:%d\n", FUNC_ADPT_ARG(padapter), reason);
			rtw_cfg80211_connect_result(pwdev, NULL, NULL, 0, NULL, 0,
				reason?reason:WLAN_STATUS_UNSPECIFIED_FAILURE,
				GFP_ATOMIC);
		} else if (pwdev->sme_state == CFG80211_SME_CONNECTED) {
			RTW_INFO(FUNC_ADPT_FMT" call cfg80211_disconnected, reason:%d\n", FUNC_ADPT_ARG(padapter), reason);
			rtw_cfg80211_disconnected(pwdev, reason, NULL, 0, locally_generated, GFP_ATOMIC);
		}

		RTW_INFO("pwdev->sme_state(a)=%d\n", pwdev->sme_state);
		#else
		if (pwdev_priv->connect_req) {
			RTW_INFO(FUNC_ADPT_FMT" call cfg80211_connect_result, reason:%d\n", FUNC_ADPT_ARG(padapter), reason);
			rtw_cfg80211_connect_result(pwdev, NULL, NULL, 0, NULL, 0,
				reason?reason:WLAN_STATUS_UNSPECIFIED_FAILURE,
				GFP_ATOMIC);
		} else {
			RTW_INFO(FUNC_ADPT_FMT" call cfg80211_disconnected, reason:%d\n", FUNC_ADPT_ARG(padapter), reason);
			rtw_cfg80211_disconnected(pwdev, reason, NULL, 0, locally_generated, GFP_ATOMIC);
		}
		#endif
	}

	rtw_wdev_free_connect_req(pwdev_priv);

	_exit_critical_bh(&pwdev_priv->connect_req_lock, &irqL);
}


#ifdef CONFIG_AP_MODE
static int rtw_cfg80211_ap_set_encryption(struct net_device *dev, struct ieee_param *param)
{
	int ret = 0;
	u32 wep_key_idx, wep_key_len;
	struct sta_info *psta = NULL, *pbcmc_sta = NULL;
	_adapter *padapter = (_adapter *)rtw_netdev_priv(dev);
	struct security_priv *psecuritypriv = &(padapter->securitypriv);
	struct sta_priv *pstapriv = &padapter->stapriv;

	RTW_INFO("%s\n", __FUNCTION__);

	param->u.crypt.err = 0;
	param->u.crypt.alg[IEEE_CRYPT_ALG_NAME_LEN - 1] = '\0';

	if (is_broadcast_mac_addr(param->sta_addr)) {
		if (param->u.crypt.idx >= WEP_KEYS
			#ifdef CONFIG_IEEE80211W
			&& param->u.crypt.idx > BIP_MAX_KEYID
			#endif
		) {
			ret = -EINVAL;
			goto exit;
		}
	} else {
		psta = rtw_get_stainfo(pstapriv, param->sta_addr);
		if (!psta) {
			ret = -EINVAL;
			RTW_INFO(FUNC_ADPT_FMT", sta "MAC_FMT" not found\n"
				, FUNC_ADPT_ARG(padapter), MAC_ARG(param->sta_addr));
			goto exit;
		}
	}

	if (strcmp(param->u.crypt.alg, "none") == 0 && (psta == NULL)) {
		/* todo:clear default encryption keys */

		RTW_INFO("clear default encryption keys, keyid=%d\n", param->u.crypt.idx);

		goto exit;
	}


	if (strcmp(param->u.crypt.alg, "WEP") == 0 && (psta == NULL)) {
		RTW_INFO("r871x_set_encryption, crypt.alg = WEP\n");

		wep_key_idx = param->u.crypt.idx;
		wep_key_len = param->u.crypt.key_len;

		RTW_INFO("r871x_set_encryption, wep_key_idx=%d, len=%d\n", wep_key_idx, wep_key_len);

		if ((wep_key_idx >= WEP_KEYS) || (wep_key_len <= 0)) {
			ret = -EINVAL;
			goto exit;
		}

		if (wep_key_len > 0)
			wep_key_len = wep_key_len <= 5 ? 5 : 13;

		if (psecuritypriv->bWepDefaultKeyIdxSet == 0) {
			/* wep default key has not been set, so use this key index as default key. */

			psecuritypriv->dot11AuthAlgrthm = dot11AuthAlgrthm_Auto;
			psecuritypriv->ndisencryptstatus = Ndis802_11Encryption1Enabled;
			psecuritypriv->dot11PrivacyAlgrthm = _WEP40_;
			psecuritypriv->dot118021XGrpPrivacy = _WEP40_;

			if (wep_key_len == 13) {
				psecuritypriv->dot11PrivacyAlgrthm = _WEP104_;
				psecuritypriv->dot118021XGrpPrivacy = _WEP104_;
			}

			psecuritypriv->dot11PrivacyKeyIndex = wep_key_idx;
		}

		_rtw_memcpy(&(psecuritypriv->dot11DefKey[wep_key_idx].skey[0]), param->u.crypt.key, wep_key_len);

		psecuritypriv->dot11DefKeylen[wep_key_idx] = wep_key_len;

		rtw_ap_set_wep_key(padapter, param->u.crypt.key, wep_key_len, wep_key_idx, 1);

		goto exit;

	}

	if (!psta) { /* group key */
		if (param->u.crypt.set_tx == 0) { /* group key, TX only */
			if (strcmp(param->u.crypt.alg, "WEP") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set WEP TX GTK idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), param->u.crypt.idx, param->u.crypt.key_len);
				_rtw_memcpy(psecuritypriv->dot118021XGrpKey[param->u.crypt.idx].skey,  param->u.crypt.key, (param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));
				psecuritypriv->dot118021XGrpPrivacy = _WEP40_;
				if (param->u.crypt.key_len == 13)
					psecuritypriv->dot118021XGrpPrivacy = _WEP104_;

			} else if (strcmp(param->u.crypt.alg, "TKIP") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set TKIP TX GTK idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), param->u.crypt.idx, param->u.crypt.key_len);
				psecuritypriv->dot118021XGrpPrivacy = _TKIP_;
				_rtw_memcpy(psecuritypriv->dot118021XGrpKey[param->u.crypt.idx].skey,  param->u.crypt.key, (param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));
				/* set mic key */
				_rtw_memcpy(psecuritypriv->dot118021XGrptxmickey[param->u.crypt.idx].skey, &(param->u.crypt.key[16]), 8);
				_rtw_memcpy(psecuritypriv->dot118021XGrprxmickey[param->u.crypt.idx].skey, &(param->u.crypt.key[24]), 8);
				psecuritypriv->busetkipkey = _TRUE;

			} else if (strcmp(param->u.crypt.alg, "CCMP") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set CCMP TX GTK idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), param->u.crypt.idx, param->u.crypt.key_len);
				psecuritypriv->dot118021XGrpPrivacy = _AES_;
				_rtw_memcpy(psecuritypriv->dot118021XGrpKey[param->u.crypt.idx].skey,  param->u.crypt.key, (param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));

			} else if (strcmp(param->u.crypt.alg, "GCMP") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set GCMP TX GTK idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), param->u.crypt.idx, param->u.crypt.key_len);
				psecuritypriv->dot118021XGrpPrivacy = _GCMP_;
				_rtw_memcpy(psecuritypriv->dot118021XGrpKey[param->u.crypt.idx].skey,
					param->u.crypt.key,
					(param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));

			} else if (strcmp(param->u.crypt.alg, "GCMP_256") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set GCMP_256 TX GTK idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), param->u.crypt.idx, param->u.crypt.key_len);
				psecuritypriv->dot118021XGrpPrivacy = _GCMP_256_;
				_rtw_memcpy(psecuritypriv->dot118021XGrpKey[param->u.crypt.idx].skey,
					param->u.crypt.key,
					(param->u.crypt.key_len > 32 ? 32 : param->u.crypt.key_len));

			} else if (strcmp(param->u.crypt.alg, "CCMP_256") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set CCMP_256 TX GTK idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), param->u.crypt.idx, param->u.crypt.key_len);
				psecuritypriv->dot118021XGrpPrivacy = _CCMP_256_;
				_rtw_memcpy(psecuritypriv->dot118021XGrpKey[param->u.crypt.idx].skey,
					param->u.crypt.key,
					(param->u.crypt.key_len > 32 ? 32: param->u.crypt.key_len));

			#ifdef CONFIG_IEEE80211W
			} else if (strcmp(param->u.crypt.alg, "BIP") == 0) {
				psecuritypriv->dot11wCipher = _BIP_CMAC_128_;
				RTW_INFO(FUNC_ADPT_FMT" set TX CMAC-128 IGTK idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), param->u.crypt.idx, param->u.crypt.key_len);
				_rtw_memcpy(padapter->securitypriv.dot11wBIPKey[param->u.crypt.idx].skey, param->u.crypt.key, (param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));
				padapter->securitypriv.dot11wBIPKeyid = param->u.crypt.idx;
				psecuritypriv->dot11wBIPtxpn.val = RTW_GET_LE64(param->u.crypt.seq);
				padapter->securitypriv.binstallBIPkey = _TRUE;
				goto exit;
			} else if (strcmp(param->u.crypt.alg, "BIP_GMAC_128") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set TX GMAC-128 IGTK idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), param->u.crypt.idx, param->u.crypt.key_len);
				psecuritypriv->dot11wCipher = _BIP_GMAC_128_;
				_rtw_memcpy(psecuritypriv->dot11wBIPKey[param->u.crypt.idx].skey,
					param->u.crypt.key, param->u.crypt.key_len);
				psecuritypriv->dot11wBIPKeyid = param->u.crypt.idx;
				psecuritypriv->dot11wBIPtxpn.val = RTW_GET_LE64(param->u.crypt.seq);
				psecuritypriv->binstallBIPkey = _TRUE;
				goto exit;
			} else if (strcmp(param->u.crypt.alg, "BIP_GMAC_256") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set TX GMAC-256 IGTK idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), param->u.crypt.idx, param->u.crypt.key_len);
				psecuritypriv->dot11wCipher = _BIP_GMAC_256_;
				_rtw_memcpy(psecuritypriv->dot11wBIPKey[param->u.crypt.idx].skey,
					param->u.crypt.key, param->u.crypt.key_len);
				padapter->securitypriv.dot11wBIPKeyid = param->u.crypt.idx;
				psecuritypriv->dot11wBIPtxpn.val = RTW_GET_LE64(param->u.crypt.seq);
				padapter->securitypriv.binstallBIPkey = _TRUE;
				goto exit;
			} else if (strcmp(param->u.crypt.alg, "BIP_CMAC_256") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set TX CMAC-256 IGTK idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), param->u.crypt.idx, param->u.crypt.key_len);
				psecuritypriv->dot11wCipher = _BIP_CMAC_256_;
				_rtw_memcpy(psecuritypriv->dot11wBIPKey[param->u.crypt.idx].skey,
					param->u.crypt.key, param->u.crypt.key_len);
				psecuritypriv->dot11wBIPKeyid = param->u.crypt.idx;
				psecuritypriv->dot11wBIPtxpn.val = RTW_GET_LE64(param->u.crypt.seq);
				psecuritypriv->binstallBIPkey = _TRUE;
				goto exit;
			#endif /* CONFIG_IEEE80211W */

			} else if (strcmp(param->u.crypt.alg, "none") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" clear group key, idx:%u\n"
					, FUNC_ADPT_ARG(padapter), param->u.crypt.idx);
				psecuritypriv->dot118021XGrpPrivacy = _NO_PRIVACY_;
			} else {
				RTW_WARN(FUNC_ADPT_FMT" set group key, not support\n"
					, FUNC_ADPT_ARG(padapter));
				goto exit;
			}

			psecuritypriv->dot118021XGrpKeyid = param->u.crypt.idx;
			pbcmc_sta = rtw_get_bcmc_stainfo(padapter);
			if (pbcmc_sta) {
				pbcmc_sta->dot11txpn.val = RTW_GET_LE64(param->u.crypt.seq);
				pbcmc_sta->ieee8021x_blocked = _FALSE;
				pbcmc_sta->dot118021XPrivacy = psecuritypriv->dot118021XGrpPrivacy; /* rx will use bmc_sta's dot118021XPrivacy			 */
			}
			psecuritypriv->binstallGrpkey = _TRUE;
			psecuritypriv->dot11PrivacyAlgrthm = psecuritypriv->dot118021XGrpPrivacy;/* !!! */

			rtw_ap_set_group_key(padapter, param->u.crypt.key, psecuritypriv->dot118021XGrpPrivacy, param->u.crypt.idx);
		}

		goto exit;

	}

	if (psecuritypriv->dot11AuthAlgrthm == dot11AuthAlgrthm_8021X && psta) { /* psk/802_1x */
		if (param->u.crypt.set_tx == 1) {
			/* pairwise key */
			if (param->u.crypt.key_len == 32)
				_rtw_memcpy(psta->dot118021x_UncstKey.skey,
						param->u.crypt.key,
						(param->u.crypt.key_len > 32 ? 32 : param->u.crypt.key_len));
			else
				_rtw_memcpy(psta->dot118021x_UncstKey.skey,
						param->u.crypt.key,
						(param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));

			if (strcmp(param->u.crypt.alg, "WEP") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set WEP PTK of "MAC_FMT" idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), MAC_ARG(psta->cmn.mac_addr)
					, param->u.crypt.idx, param->u.crypt.key_len);
				psta->dot118021XPrivacy = _WEP40_;
				if (param->u.crypt.key_len == 13)
					psta->dot118021XPrivacy = _WEP104_;

			} else if (strcmp(param->u.crypt.alg, "TKIP") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set TKIP PTK of "MAC_FMT" idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), MAC_ARG(psta->cmn.mac_addr)
					, param->u.crypt.idx, param->u.crypt.key_len);
				psta->dot118021XPrivacy = _TKIP_;
				/* set mic key */
				_rtw_memcpy(psta->dot11tkiptxmickey.skey, &(param->u.crypt.key[16]), 8);
				_rtw_memcpy(psta->dot11tkiprxmickey.skey, &(param->u.crypt.key[24]), 8);
				psecuritypriv->busetkipkey = _TRUE;

			} else if (strcmp(param->u.crypt.alg, "CCMP") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set CCMP PTK of "MAC_FMT" idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), MAC_ARG(psta->cmn.mac_addr)
					, param->u.crypt.idx, param->u.crypt.key_len);
				psta->dot118021XPrivacy = _AES_;

			} else if (strcmp(param->u.crypt.alg, "GCMP") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set GCMP PTK of "MAC_FMT" idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), MAC_ARG(psta->cmn.mac_addr)
					, param->u.crypt.idx, param->u.crypt.key_len);
				psta->dot118021XPrivacy = _GCMP_;

			} else if (strcmp(param->u.crypt.alg, "GCMP_256") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set GCMP_256 PTK of "MAC_FMT" idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), MAC_ARG(psta->cmn.mac_addr)
					, param->u.crypt.idx, param->u.crypt.key_len);
				psta->dot118021XPrivacy = _GCMP_256_;

			} else if (strcmp(param->u.crypt.alg, "CCMP_256") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set CCMP_256 PTK of "MAC_FMT" idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), MAC_ARG(psta->cmn.mac_addr)
					, param->u.crypt.idx, param->u.crypt.key_len);
				psta->dot118021XPrivacy = _CCMP_256_;

			} else if (strcmp(param->u.crypt.alg, "none") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" clear pairwise key of "MAC_FMT" idx:%u\n"
					, FUNC_ADPT_ARG(padapter), MAC_ARG(psta->cmn.mac_addr)
					, param->u.crypt.idx);
				psta->dot118021XPrivacy = _NO_PRIVACY_;
			} else {
				RTW_WARN(FUNC_ADPT_FMT" set pairwise key of "MAC_FMT", not support\n"
					, FUNC_ADPT_ARG(padapter), MAC_ARG(psta->cmn.mac_addr));
				goto exit;
			}

			psta->dot11txpn.val = RTW_GET_LE64(param->u.crypt.seq);
			psta->dot11rxpn.val = RTW_GET_LE64(param->u.crypt.seq);
			psta->ieee8021x_blocked = _FALSE;

			if (psta->dot118021XPrivacy != _NO_PRIVACY_) {
				psta->bpairwise_key_installed = _TRUE;

				/* WPA2 key-handshake has completed */
				if (psecuritypriv->ndisauthtype == Ndis802_11AuthModeWPA2PSK)
					psta->state &= (~WIFI_UNDER_KEY_HANDSHAKE);
			}

			rtw_ap_set_pairwise_key(padapter, psta);
		} else {
			/* peer's group key, RX only */
			#ifdef CONFIG_RTW_MESH
			if (strcmp(param->u.crypt.alg, "CCMP") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set CCMP GTK of "MAC_FMT", idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), MAC_ARG(psta->cmn.mac_addr)
					, param->u.crypt.idx, param->u.crypt.key_len);
				psta->group_privacy = _AES_;
				_rtw_memcpy(psta->gtk.skey, param->u.crypt.key, (param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));
				psta->gtk_bmp |= BIT(param->u.crypt.idx);
				psta->gtk_pn.val = RTW_GET_LE64(param->u.crypt.seq);

			} else if (strcmp(param->u.crypt.alg, "GCMP") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set GCMP GTK of "MAC_FMT", idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), MAC_ARG(psta->cmn.mac_addr)
					, param->u.crypt.idx, param->u.crypt.key_len);
				psta->group_privacy = _GCMP_;
				_rtw_memcpy(psta->gtk.skey, param->u.crypt.key, (param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));
				psta->gtk_bmp |= BIT(param->u.crypt.idx);
				psta->gtk_pn.val = RTW_GET_LE64(param->u.crypt.seq);

			} else if (strcmp(param->u.crypt.alg, "CCMP_256") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set CCMP_256 GTK of "MAC_FMT", idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), MAC_ARG(psta->cmn.mac_addr)
					, param->u.crypt.idx, param->u.crypt.key_len);
				psta->group_privacy = _CCMP_256_;
				_rtw_memcpy(psta->gtk.skey, param->u.crypt.key, (param->u.crypt.key_len > 32 ? 32 : param->u.crypt.key_len));
				psta->gtk_bmp |= BIT(param->u.crypt.idx);
				psta->gtk_pn.val = RTW_GET_LE64(param->u.crypt.seq);

			} else if (strcmp(param->u.crypt.alg, "GCMP_256") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set GCMP_256 GTK of "MAC_FMT", idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), MAC_ARG(psta->cmn.mac_addr)
					, param->u.crypt.idx, param->u.crypt.key_len);
				psta->group_privacy = _GCMP_256_;
				_rtw_memcpy(psta->gtk.skey, param->u.crypt.key, (param->u.crypt.key_len > 32 ? 32 : param->u.crypt.key_len));
				psta->gtk_bmp |= BIT(param->u.crypt.idx);
				psta->gtk_pn.val = RTW_GET_LE64(param->u.crypt.seq);

			#ifdef CONFIG_IEEE80211W
			} else if (strcmp(param->u.crypt.alg, "BIP") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set CMAC-128 IGTK of "MAC_FMT", idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), MAC_ARG(psta->cmn.mac_addr)
					, param->u.crypt.idx, param->u.crypt.key_len);
				psta->dot11wCipher = _BIP_CMAC_128_;
				_rtw_memcpy(psta->igtk.skey, param->u.crypt.key, (param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));
				psta->igtk_bmp |= BIT(param->u.crypt.idx);
				psta->igtk_id = param->u.crypt.idx;
				psta->igtk_pn.val = RTW_GET_LE64(param->u.crypt.seq);
				goto exit;

			} else if (strcmp(param->u.crypt.alg, "BIP_GMAC_128") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set GMAC-128 IGTK of "MAC_FMT", idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), MAC_ARG(psta->cmn.mac_addr)
					, param->u.crypt.idx, param->u.crypt.key_len);
				psta->dot11wCipher = _BIP_GMAC_128_;
				_rtw_memcpy(psta->igtk.skey, param->u.crypt.key, (param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));
				psta->igtk_bmp |= BIT(param->u.crypt.idx);
				psta->igtk_id = param->u.crypt.idx;
				psta->igtk_pn.val = RTW_GET_LE64(param->u.crypt.seq);
				goto exit;

			} else if (strcmp(param->u.crypt.alg, "BIP_CMAC_256") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set CMAC-256 IGTK of "MAC_FMT", idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), MAC_ARG(psta->cmn.mac_addr)
					, param->u.crypt.idx, param->u.crypt.key_len);
				psta->dot11wCipher = _BIP_CMAC_256_;
				_rtw_memcpy(psta->igtk.skey, param->u.crypt.key, (param->u.crypt.key_len > 32 ? 32 : param->u.crypt.key_len));
				psta->igtk_bmp |= BIT(param->u.crypt.idx);
				psta->igtk_id = param->u.crypt.idx;
				psta->igtk_pn.val = RTW_GET_LE64(param->u.crypt.seq);
				goto exit;

			} else if (strcmp(param->u.crypt.alg, "BIP_GMAC_256") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" set GMAC-256 IGTK of "MAC_FMT", idx:%u, len:%u\n"
					, FUNC_ADPT_ARG(padapter), MAC_ARG(psta->cmn.mac_addr)
					, param->u.crypt.idx, param->u.crypt.key_len);
				psta->dot11wCipher = _BIP_GMAC_256_;
				_rtw_memcpy(psta->igtk.skey, param->u.crypt.key, (param->u.crypt.key_len > 32 ? 32 : param->u.crypt.key_len));
				psta->igtk_bmp |= BIT(param->u.crypt.idx);
				psta->igtk_id = param->u.crypt.idx;
				psta->igtk_pn.val = RTW_GET_LE64(param->u.crypt.seq);
				goto exit;
			#endif /* CONFIG_IEEE80211W */

			} else if (strcmp(param->u.crypt.alg, "none") == 0) {
				RTW_INFO(FUNC_ADPT_FMT" clear group key of "MAC_FMT", idx:%u\n"
					, FUNC_ADPT_ARG(padapter), MAC_ARG(psta->cmn.mac_addr)
					, param->u.crypt.idx);
				psta->group_privacy = _NO_PRIVACY_;
				psta->gtk_bmp &= ~BIT(param->u.crypt.idx);
			} else
			#endif /* CONFIG_RTW_MESH */
			{
				RTW_WARN(FUNC_ADPT_FMT" set group key of "MAC_FMT", not support\n"
					, FUNC_ADPT_ARG(padapter), MAC_ARG(psta->cmn.mac_addr));
				goto exit;
			}

			#ifdef CONFIG_RTW_MESH
			rtw_ap_set_sta_key(padapter, psta->cmn.mac_addr, psta->group_privacy
				, param->u.crypt.key, param->u.crypt.idx, 1);
			#endif
		}

	}

exit:
	return ret;
}
#endif /* CONFIG_AP_MODE */

static int rtw_cfg80211_set_encryption(struct net_device *dev, struct ieee_param *param)
{
	int ret = 0;
	u32 wep_key_idx, wep_key_len;
	_adapter *padapter = (_adapter *)rtw_netdev_priv(dev);
	struct mlme_priv	*pmlmepriv = &padapter->mlmepriv;
	struct security_priv *psecuritypriv = &padapter->securitypriv;
#ifdef CONFIG_P2P
	struct wifidirect_info *pwdinfo = &padapter->wdinfo;
#endif /* CONFIG_P2P */

	RTW_INFO("%s\n", __func__);

	param->u.crypt.err = 0;
	param->u.crypt.alg[IEEE_CRYPT_ALG_NAME_LEN - 1] = '\0';

	if (is_broadcast_mac_addr(param->sta_addr)) {
		if (param->u.crypt.idx >= WEP_KEYS
			#ifdef CONFIG_IEEE80211W
			&& param->u.crypt.idx > BIP_MAX_KEYID
			#endif
		) {
			ret = -EINVAL;
			goto exit;
		}
	} else {
#ifdef CONFIG_WAPI_SUPPORT
		if (strcmp(param->u.crypt.alg, "SMS4"))
#endif
		{
			ret = -EINVAL;
			goto exit;
		}
	}

	if (strcmp(param->u.crypt.alg, "WEP") == 0) {
		RTW_INFO("wpa_set_encryption, crypt.alg = WEP\n");

		wep_key_idx = param->u.crypt.idx;
		wep_key_len = param->u.crypt.key_len;

		if ((wep_key_idx >= WEP_KEYS) || (wep_key_len <= 0)) {
			ret = -EINVAL;
			goto exit;
		}

		if (psecuritypriv->bWepDefaultKeyIdxSet == 0) {
			/* wep default key has not been set, so use this key index as default key. */

			wep_key_len = wep_key_len <= 5 ? 5 : 13;

			psecuritypriv->ndisencryptstatus = Ndis802_11Encryption1Enabled;
			psecuritypriv->dot11PrivacyAlgrthm = _WEP40_;
			psecuritypriv->dot118021XGrpPrivacy = _WEP40_;

			if (wep_key_len == 13) {
				psecuritypriv->dot11PrivacyAlgrthm = _WEP104_;
				psecuritypriv->dot118021XGrpPrivacy = _WEP104_;
			}

			psecuritypriv->dot11PrivacyKeyIndex = wep_key_idx;
		}

		_rtw_memcpy(&(psecuritypriv->dot11DefKey[wep_key_idx].skey[0]), param->u.crypt.key, wep_key_len);

		psecuritypriv->dot11DefKeylen[wep_key_idx] = wep_key_len;

		rtw_set_key(padapter, psecuritypriv, wep_key_idx, 0, _TRUE);

		goto exit;
	}

	if (padapter->securitypriv.dot11AuthAlgrthm == dot11AuthAlgrthm_8021X) { /* 802_1x */
		struct sta_info *psta, *pbcmc_sta;
		struct sta_priv *pstapriv = &padapter->stapriv;

		/* RTW_INFO("%s, : dot11AuthAlgrthm == dot11AuthAlgrthm_8021X\n", __func__); */

		if (check_fwstate(pmlmepriv, WIFI_STATION_STATE | WIFI_MP_STATE) == _TRUE) { /* sta mode */
#ifdef CONFIG_RTW_80211R
			if (rtw_ft_roam(padapter))
				psta = rtw_get_stainfo(pstapriv, pmlmepriv->assoc_bssid);
			else
#endif
				psta = rtw_get_stainfo(pstapriv, get_bssid(pmlmepriv));
			if (psta == NULL) {
				/* DEBUG_ERR( ("Set wpa_set_encryption: Obtain Sta_info fail\n")); */
				RTW_INFO("%s, : Obtain Sta_info fail\n", __func__);
			} else {
				/* Jeff: don't disable ieee8021x_blocked while clearing key */
				if (strcmp(param->u.crypt.alg, "none") != 0)
					psta->ieee8021x_blocked = _FALSE;

				if ((padapter->securitypriv.ndisencryptstatus == Ndis802_11Encryption2Enabled) ||
				    (padapter->securitypriv.ndisencryptstatus ==  Ndis802_11Encryption3Enabled))
					psta->dot118021XPrivacy = padapter->securitypriv.dot11PrivacyAlgrthm;

				if (param->u.crypt.set_tx == 1) { /* pairwise key */
					RTW_INFO(FUNC_ADPT_FMT" set %s PTK idx:%u, len:%u\n"
						, FUNC_ADPT_ARG(padapter), param->u.crypt.alg, param->u.crypt.idx, param->u.crypt.key_len);

					if (strcmp(param->u.crypt.alg, "GCMP_256") == 0
						|| strcmp(param->u.crypt.alg, "CCMP_256") == 0) {
						_rtw_memcpy(psta->dot118021x_UncstKey.skey,
							param->u.crypt.key,
							((param->u.crypt.key_len > 32) ?
								32 : param->u.crypt.key_len));
					} else
						_rtw_memcpy(psta->dot118021x_UncstKey.skey,
							param->u.crypt.key,
							(param->u.crypt.key_len > 16 ?
								16 : param->u.crypt.key_len));

					if (strcmp(param->u.crypt.alg, "TKIP") == 0) { /* set mic key */
						_rtw_memcpy(psta->dot11tkiptxmickey.skey, &(param->u.crypt.key[16]), 8);
						_rtw_memcpy(psta->dot11tkiprxmickey.skey, &(param->u.crypt.key[24]), 8);
						padapter->securitypriv.busetkipkey = _FALSE;
					}
					psta->dot11txpn.val = RTW_GET_LE64(param->u.crypt.seq);
					psta->dot11rxpn.val = RTW_GET_LE64(param->u.crypt.seq);
					psta->bpairwise_key_installed = _TRUE;
					#ifdef CONFIG_RTW_80211R
					psta->ft_pairwise_key_installed = _TRUE;
					#endif
					rtw_setstakey_cmd(padapter, psta, UNICAST_KEY, _TRUE);

				} else { /* group key */
					if (strcmp(param->u.crypt.alg, "TKIP") == 0
						|| strcmp(param->u.crypt.alg, "CCMP") == 0
						|| strcmp(param->u.crypt.alg, "GCMP") == 0) {
						RTW_INFO(FUNC_ADPT_FMT" set %s GTK idx:%u, len:%u\n"
							, FUNC_ADPT_ARG(padapter), param->u.crypt.alg, param->u.crypt.idx, param->u.crypt.key_len);
						_rtw_memcpy(padapter->securitypriv.dot118021XGrpKey[param->u.crypt.idx].skey,
							param->u.crypt.key,
							(param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));
						_rtw_memcpy(padapter->securitypriv.dot118021XGrptxmickey[param->u.crypt.idx].skey, &(param->u.crypt.key[16]), 8);
						_rtw_memcpy(padapter->securitypriv.dot118021XGrprxmickey[param->u.crypt.idx].skey, &(param->u.crypt.key[24]), 8);
						padapter->securitypriv.binstallGrpkey = _TRUE;
						if (param->u.crypt.idx < 4) 
							_rtw_memcpy(padapter->securitypriv.iv_seq[param->u.crypt.idx], param->u.crypt.seq, 8);							
						padapter->securitypriv.dot118021XGrpKeyid = param->u.crypt.idx;
						rtw_set_key(padapter, &padapter->securitypriv, param->u.crypt.idx, 1, _TRUE);
					} else if (strcmp(param->u.crypt.alg, "GCMP_256") == 0
						|| strcmp(param->u.crypt.alg, "CCMP_256") == 0) {
						RTW_INFO(FUNC_ADPT_FMT" set %s GTK idx:%u, len:%u\n"
							, FUNC_ADPT_ARG(padapter), param->u.crypt.alg, param->u.crypt.idx, param->u.crypt.key_len);
						_rtw_memcpy(
							padapter->securitypriv.dot118021XGrpKey[param->u.crypt.idx].skey,
							param->u.crypt.key,
							(param->u.crypt.key_len > 32 ? 32 : param->u.crypt.key_len));
						padapter->securitypriv.binstallGrpkey = _TRUE;
						padapter->securitypriv.dot118021XGrpKeyid = param->u.crypt.idx;
						rtw_set_key(padapter, &padapter->securitypriv, param->u.crypt.idx, 1, _TRUE);
					#ifdef CONFIG_IEEE80211W
					} else if (strcmp(param->u.crypt.alg, "BIP") == 0) {
						psecuritypriv->dot11wCipher = _BIP_CMAC_128_;
						RTW_INFO(FUNC_ADPT_FMT" set CMAC-128 IGTK idx:%u, len:%u\n"
							, FUNC_ADPT_ARG(padapter), param->u.crypt.idx, param->u.crypt.key_len);
						_rtw_memcpy(padapter->securitypriv.dot11wBIPKey[param->u.crypt.idx].skey,
							param->u.crypt.key,
							(param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));
						psecuritypriv->dot11wBIPKeyid = param->u.crypt.idx;
						psecuritypriv->dot11wBIPrxpn.val = RTW_GET_LE64(param->u.crypt.seq);
						psecuritypriv->binstallBIPkey = _TRUE;
					} else if (strcmp(param->u.crypt.alg, "BIP_GMAC_128") == 0) {
						psecuritypriv->dot11wCipher = _BIP_GMAC_128_;
						RTW_INFO(FUNC_ADPT_FMT" set GMAC-128 IGTK idx:%u, len:%u\n"
							, FUNC_ADPT_ARG(padapter), param->u.crypt.idx, param->u.crypt.key_len);
						_rtw_memcpy(padapter->securitypriv.dot11wBIPKey[param->u.crypt.idx].skey,
							param->u.crypt.key,
							(param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));
						psecuritypriv->dot11wBIPKeyid = param->u.crypt.idx;
						psecuritypriv->dot11wBIPrxpn.val = RTW_GET_LE64(param->u.crypt.seq);
						psecuritypriv->binstallBIPkey = _TRUE;
					} else if (strcmp(param->u.crypt.alg, "BIP_GMAC_256") == 0) {
						psecuritypriv->dot11wCipher = _BIP_GMAC_256_;
						RTW_INFO(FUNC_ADPT_FMT" set GMAC-256 IGTK idx:%u, len:%u\n"
							, FUNC_ADPT_ARG(padapter), param->u.crypt.idx, param->u.crypt.key_len);
						_rtw_memcpy(padapter->securitypriv.dot11wBIPKey[param->u.crypt.idx].skey,
							param->u.crypt.key,
							(param->u.crypt.key_len > 32 ? 32 : param->u.crypt.key_len));
						psecuritypriv->dot11wBIPKeyid = param->u.crypt.idx;
						psecuritypriv->dot11wBIPrxpn.val = RTW_GET_LE64(param->u.crypt.seq);
						psecuritypriv->binstallBIPkey = _TRUE;
					} else if (strcmp(param->u.crypt.alg, "BIP_CMAC_256") == 0) {
						psecuritypriv->dot11wCipher = _BIP_CMAC_256_;
						RTW_INFO(FUNC_ADPT_FMT" set CMAC-256 IGTK idx:%u, len:%u\n"
							, FUNC_ADPT_ARG(padapter), param->u.crypt.idx, param->u.crypt.key_len);
						_rtw_memcpy(psecuritypriv->dot11wBIPKey[param->u.crypt.idx].skey,
							param->u.crypt.key, param->u.crypt.key_len);
						psecuritypriv->dot11wBIPKeyid = param->u.crypt.idx;
						psecuritypriv->dot11wBIPrxpn.val = RTW_GET_LE64(param->u.crypt.seq);
						psecuritypriv->binstallBIPkey = _TRUE;
					#endif /* CONFIG_IEEE80211W */

					}

#ifdef CONFIG_P2P
					if (pwdinfo->driver_interface == DRIVER_CFG80211) {
						if (rtw_p2p_chk_state(pwdinfo, P2P_STATE_PROVISIONING_ING))
							rtw_p2p_set_state(pwdinfo, P2P_STATE_PROVISIONING_DONE);
					}
#endif /* CONFIG_P2P */

					/* WPA/WPA2 key-handshake has completed */
					clr_fwstate(pmlmepriv, WIFI_UNDER_KEY_HANDSHAKE);

				}
			}

			pbcmc_sta = rtw_get_bcmc_stainfo(padapter);
			if (pbcmc_sta == NULL) {
				/* DEBUG_ERR( ("Set OID_802_11_ADD_KEY: bcmc stainfo is null\n")); */
			} else {
				/* Jeff: don't disable ieee8021x_blocked while clearing key */
				if (strcmp(param->u.crypt.alg, "none") != 0)
					pbcmc_sta->ieee8021x_blocked = _FALSE;

				if ((padapter->securitypriv.ndisencryptstatus == Ndis802_11Encryption2Enabled) ||
				    (padapter->securitypriv.ndisencryptstatus ==  Ndis802_11Encryption3Enabled))
					pbcmc_sta->dot118021XPrivacy = padapter->securitypriv.dot11PrivacyAlgrthm;
			}
		} else if (check_fwstate(pmlmepriv, WIFI_ADHOC_STATE)) { /* adhoc mode */
		}
	}

	#ifdef CONFIG_WAPI_SUPPORT
	if (strcmp(param->u.crypt.alg, "SMS4") == 0)
		rtw_wapi_set_set_encryption(padapter, param);
	#endif

exit:

	RTW_INFO("%s, ret=%d\n", __func__, ret);


	return ret;
}

static int cfg80211_rtw_add_key(struct wiphy *wiphy, struct net_device *ndev
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	, int link_id
#endif
	, u8 key_index
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE)
	, bool pairwise
#endif
	, const u8 *mac_addr, struct key_params *params)
{
	char *alg_name;
	u32 param_len;
	struct ieee_param *param = NULL;
	int ret = 0;
	_adapter *padapter = (_adapter *)rtw_netdev_priv(ndev);
	struct wireless_dev *rtw_wdev = padapter->rtw_wdev;
	struct mlme_priv *pmlmepriv = &padapter->mlmepriv;
#ifdef CONFIG_TDLS
	struct sta_info *ptdls_sta;
#endif /* CONFIG_TDLS */

	if (mac_addr)
		RTW_INFO(FUNC_NDEV_FMT" adding key for %pM\n", FUNC_NDEV_ARG(ndev), mac_addr);
	RTW_INFO(FUNC_NDEV_FMT" cipher=0x%x\n", FUNC_NDEV_ARG(ndev), params->cipher);
	RTW_INFO(FUNC_NDEV_FMT" key_len=%d, key_index=%d\n", FUNC_NDEV_ARG(ndev), params->key_len, key_index);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE)
	RTW_INFO(FUNC_NDEV_FMT" pairwise=%d\n", FUNC_NDEV_ARG(ndev), pairwise);
#endif

	if (rtw_cfg80211_sync_iftype(padapter) != _SUCCESS) {
		ret = -ENOTSUPP;
		goto addkey_end;
	}

	param_len = sizeof(struct ieee_param) + params->key_len;
	param = rtw_malloc(param_len);
	if (param == NULL)
		return -1;

	_rtw_memset(param, 0, param_len);

	param->cmd = IEEE_CMD_SET_ENCRYPTION;
	_rtw_memset(param->sta_addr, 0xff, ETH_ALEN);

	switch (params->cipher) {
	case IW_AUTH_CIPHER_NONE:
		/* todo: remove key */
		/* remove = 1;	 */
		alg_name = "none";
		break;
	case WLAN_CIPHER_SUITE_WEP40:
	case WLAN_CIPHER_SUITE_WEP104:
		alg_name = "WEP";
		break;
	case WLAN_CIPHER_SUITE_TKIP:
		alg_name = "TKIP";
		break;
	case WLAN_CIPHER_SUITE_CCMP:
		alg_name = "CCMP";
		break;
	case WIFI_CIPHER_SUITE_GCMP:
		alg_name = "GCMP";
		break;
	case WIFI_CIPHER_SUITE_GCMP_256:
		alg_name = "GCMP_256";
		break;
	case WIFI_CIPHER_SUITE_CCMP_256:
		alg_name = "CCMP_256";
		break;
#ifdef CONFIG_IEEE80211W
	case WLAN_CIPHER_SUITE_AES_CMAC:
		alg_name = "BIP";
		break;
	case WIFI_CIPHER_SUITE_BIP_GMAC_128:
		alg_name = "BIP_GMAC_128";
		break;
	case WIFI_CIPHER_SUITE_BIP_GMAC_256:
		alg_name = "BIP_GMAC_256";
		break;
	case WIFI_CIPHER_SUITE_BIP_CMAC_256:
		alg_name = "BIP_CMAC_256";
		break;
#endif /* CONFIG_IEEE80211W */
#ifdef CONFIG_WAPI_SUPPORT
	case WLAN_CIPHER_SUITE_SMS4:
		alg_name = "SMS4";
		if (pairwise == NL80211_KEYTYPE_PAIRWISE) {
			if (key_index != 0 && key_index != 1) {
				ret = -ENOTSUPP;
				goto addkey_end;
			}
			_rtw_memcpy((void *)param->sta_addr, (void *)mac_addr, ETH_ALEN);
		} else
			RTW_INFO("mac_addr is null\n");
		RTW_INFO("rtw_wx_set_enc_ext: SMS4 case\n");
		break;
#endif

	default:
		ret = -ENOTSUPP;
		goto addkey_end;
	}

	strncpy((char *)param->u.crypt.alg, alg_name, IEEE_CRYPT_ALG_NAME_LEN);


	if (!mac_addr || is_broadcast_ether_addr(mac_addr)
		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE)
		|| !pairwise
		#endif
	) {
		param->u.crypt.set_tx = 0; /* for wpa/wpa2 group key */
	} else {
		param->u.crypt.set_tx = 1; /* for wpa/wpa2 pairwise key */
	}

	param->u.crypt.idx = key_index;

	if (params->seq_len && params->seq) {
		_rtw_memcpy(param->u.crypt.seq, (u8 *)params->seq, params->seq_len);
		RTW_INFO(FUNC_NDEV_FMT" seq_len:%u, seq:0x%llx\n", FUNC_NDEV_ARG(ndev)
			, params->seq_len, RTW_GET_LE64(param->u.crypt.seq));
	}

	if (params->key_len && params->key) {
		param->u.crypt.key_len = params->key_len;
		_rtw_memcpy(param->u.crypt.key, (u8 *)params->key, params->key_len);
	}

	if (check_fwstate(pmlmepriv, WIFI_STATION_STATE) == _TRUE) {
#ifdef CONFIG_TDLS
		if (rtw_tdls_is_driver_setup(padapter) == _FALSE && mac_addr) {
			ptdls_sta = rtw_get_stainfo(&padapter->stapriv, (void *)mac_addr);
			if (ptdls_sta != NULL && ptdls_sta->tdls_sta_state) {
				_rtw_memcpy(ptdls_sta->tpk.tk, params->key, params->key_len);
				rtw_tdls_set_key(padapter, ptdls_sta);
				goto addkey_end;
			}
		}
#endif /* CONFIG_TDLS */
		ret = rtw_cfg80211_set_encryption(ndev, param);
	} else if (MLME_IS_AP(padapter) || MLME_IS_MESH(padapter)) {
#ifdef CONFIG_AP_MODE
		if (mac_addr)
			_rtw_memcpy(param->sta_addr, (void *)mac_addr, ETH_ALEN);

		ret = rtw_cfg80211_ap_set_encryption(ndev, param);
#endif
	} else if (check_fwstate(pmlmepriv, WIFI_ADHOC_STATE) == _TRUE
		|| check_fwstate(pmlmepriv, WIFI_ADHOC_MASTER_STATE) == _TRUE
	) {
		/* RTW_INFO("@@@@@@@@@@ fw_state=0x%x, iftype=%d\n", pmlmepriv->fw_state, rtw_wdev->iftype); */
		ret = rtw_cfg80211_set_encryption(ndev, param);
	} else
		RTW_INFO("error! fw_state=0x%x, iftype=%d\n", pmlmepriv->fw_state, rtw_wdev->iftype);


addkey_end:
	if (param)
		rtw_mfree(param, param_len);

	return ret;

}

static int cfg80211_rtw_get_key(struct wiphy *wiphy, struct net_device *ndev
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	, int link_id
#endif
	, u8 keyid
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE)
	, bool pairwise
#endif
	, const u8 *mac_addr, void *cookie
	, void (*callback)(void *cookie, struct key_params *))
{
#define GET_KEY_PARAM_FMT_S " keyid=%d"
#define GET_KEY_PARAM_ARG_S , keyid
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE)
	#define GET_KEY_PARAM_FMT_2_6_37 ", pairwise=%d"
	#define GET_KEY_PARAM_ARG_2_6_37 , pairwise
#else
	#define GET_KEY_PARAM_FMT_2_6_37 ""
	#define GET_KEY_PARAM_ARG_2_6_37
#endif
#define GET_KEY_PARAM_FMT_E ", addr=%pM"
#define GET_KEY_PARAM_ARG_E , mac_addr

	_adapter *adapter = (_adapter *)rtw_netdev_priv(ndev);
	struct security_priv *sec = &adapter->securitypriv;
	struct sta_priv *stapriv = &adapter->stapriv;
	struct sta_info *sta = NULL;
	u32 cipher = _NO_PRIVACY_;
	union Keytype *key = NULL;
	u8 key_len = 0;
	u64 *pn = NULL;
	u8 pn_len = 0;
	u8 pn_val[8] = {0};

	struct key_params params;
	int ret = -ENOENT;

	if (keyid >= WEP_KEYS
		#ifdef CONFIG_IEEE80211W
		&& keyid > BIP_MAX_KEYID
		#endif
	)
		goto exit;

	if (!mac_addr || is_broadcast_ether_addr(mac_addr)
		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE)
		|| (MLME_IS_STA(adapter) && !pairwise)
		#endif
	) {
		/* WEP key, TX GTK/IGTK, RX GTK/IGTK(for STA mode) */
		if (is_wep_enc(sec->dot118021XGrpPrivacy)) {
			if (keyid >= WEP_KEYS)
				goto exit;
			if (!(sec->key_mask & BIT(keyid)))
				goto exit;
			cipher = sec->dot118021XGrpPrivacy;
			key = &sec->dot11DefKey[keyid];
		} else {
			if (keyid < WEP_KEYS) {
				if (sec->binstallGrpkey != _TRUE)
					goto exit;
				cipher = sec->dot118021XGrpPrivacy;
				key = &sec->dot118021XGrpKey[keyid];
				sta = rtw_get_bcmc_stainfo(adapter);
				if (sta)
					pn = &sta->dot11txpn.val;
			#ifdef CONFIG_IEEE80211W
			} else if (keyid <= BIP_MAX_KEYID) {
				if (SEC_IS_BIP_KEY_INSTALLED(sec) != _TRUE)
					goto exit;
				cipher = sec->dot11wCipher;
				key = &sec->dot11wBIPKey[keyid];
				pn = &sec->dot11wBIPtxpn.val;
			#endif
			}
		}
	} else {
		/* Pairwise key, RX GTK/IGTK for specific peer */
		sta = rtw_get_stainfo(stapriv, mac_addr);
		if (!sta)
			goto exit;

		if (keyid < WEP_KEYS && pairwise) {
			if (sta->bpairwise_key_installed != _TRUE)
				goto exit;
			cipher = sta->dot118021XPrivacy;
			key = &sta->dot118021x_UncstKey;
		#ifdef CONFIG_RTW_MESH
		} else if (keyid < WEP_KEYS && !pairwise) {
			if (!(sta->gtk_bmp & BIT(keyid)))
				goto exit;
			cipher = sta->group_privacy;
			key = &sta->gtk;
		#ifdef CONFIG_IEEE80211W
		} else if (keyid <= BIP_MAX_KEYID && !pairwise) {
			if (!(sta->igtk_bmp & BIT(keyid)))
				goto exit;
			cipher = sta->dot11wCipher;
			key = &sta->igtk;
			pn = &sta->igtk_pn.val;
		#endif
		#endif /* CONFIG_RTW_MESH */
		}
	}

	if (!key)
		goto exit;

	if (cipher == _WEP40_) {
		cipher = WLAN_CIPHER_SUITE_WEP40;
		key_len = sec->dot11DefKeylen[keyid];
	} else if (cipher == _WEP104_) {
		cipher = WLAN_CIPHER_SUITE_WEP104;
		key_len = sec->dot11DefKeylen[keyid];
	} else if (cipher == _TKIP_ || cipher == _TKIP_WTMIC_) {
		cipher = WLAN_CIPHER_SUITE_TKIP;
		key_len = 16;
	} else if (cipher == _AES_) {
		cipher = WLAN_CIPHER_SUITE_CCMP;
		key_len = 16;
#ifdef CONFIG_WAPI_SUPPORT
	} else if (cipher == _SMS4_) {
		cipher = WLAN_CIPHER_SUITE_SMS4;
		key_len = 16;
#endif
	} else if (cipher == _GCMP_) {
		cipher = WIFI_CIPHER_SUITE_GCMP;
		key_len = 16;
	} else if (cipher == _CCMP_256_) {
		cipher = WIFI_CIPHER_SUITE_CCMP_256;
		key_len = 32;
	} else if (cipher == _GCMP_256_) {
		cipher = WIFI_CIPHER_SUITE_GCMP_256;
		key_len = 32;
	#ifdef CONFIG_IEEE80211W
	} else if (cipher == _BIP_CMAC_128_) {
		cipher = WLAN_CIPHER_SUITE_AES_CMAC;
		key_len = 16;
	} else if (cipher == _BIP_GMAC_128_) {
		cipher = WIFI_CIPHER_SUITE_BIP_GMAC_128;
		key_len = 16;
	} else if (cipher == _BIP_GMAC_256_) {
		cipher = WIFI_CIPHER_SUITE_BIP_GMAC_256;
		key_len = 32;
	} else if (cipher == _BIP_CMAC_256_) {
		cipher = WIFI_CIPHER_SUITE_BIP_CMAC_256;
		key_len = 32;
	#endif
	} else {
		RTW_WARN(FUNC_NDEV_FMT" unknown cipher:%u\n", FUNC_NDEV_ARG(ndev), cipher);
		rtw_warn_on(1);
		goto exit;
	}

	if (pn) {
		*((u64 *)pn_val) = cpu_to_le64(*pn);
		pn_len = 6;
	}

	ret = 0;

exit:
	RTW_INFO(FUNC_NDEV_FMT
		GET_KEY_PARAM_FMT_S
		GET_KEY_PARAM_FMT_2_6_37
		GET_KEY_PARAM_FMT_E
		" ret %d\n", FUNC_NDEV_ARG(ndev)
		GET_KEY_PARAM_ARG_S
		GET_KEY_PARAM_ARG_2_6_37
		GET_KEY_PARAM_ARG_E
		, ret);
	if (pn)
		RTW_INFO(FUNC_NDEV_FMT " seq:0x%llx\n", FUNC_NDEV_ARG(ndev), *pn);

	if (ret == 0) {
		_rtw_memset(&params, 0, sizeof(params));

		params.cipher = cipher;
		params.key = key->skey;
		params.key_len = key_len;
		if (pn) {
			params.seq = pn_val;
			params.seq_len = pn_len;
		}

		callback(cookie, &params);
	}

	return ret;
}

static int cfg80211_rtw_del_key(struct wiphy *wiphy, struct net_device *ndev,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	int link_id,
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE)
				u8 key_index, bool pairwise, const u8 *mac_addr)
#else	/* (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) */
				u8 key_index, const u8 *mac_addr)
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) */
{
	_adapter *padapter = (_adapter *)rtw_netdev_priv(ndev);
	struct security_priv *psecuritypriv = &padapter->securitypriv;

	RTW_INFO(FUNC_NDEV_FMT" key_index=%d, addr=%pM\n", FUNC_NDEV_ARG(ndev), key_index, mac_addr);

	if (key_index == psecuritypriv->dot11PrivacyKeyIndex) {
		/* clear the flag of wep default key set. */
		psecuritypriv->bWepDefaultKeyIdxSet = 0;
	}

	return 0;
}

static int cfg80211_rtw_set_default_key(struct wiphy *wiphy,
	struct net_device *ndev,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	int link_id,
#endif
	u8 key_index
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)) || defined(COMPAT_KERNEL_RELEASE)
	, bool unicast, bool multicast
	#endif
)
{
	_adapter *padapter = (_adapter *)rtw_netdev_priv(ndev);
	struct security_priv *psecuritypriv = &padapter->securitypriv;

#define SET_DEF_KEY_PARAM_FMT " key_index=%d"
#define SET_DEF_KEY_PARAM_ARG , key_index
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)) || defined(COMPAT_KERNEL_RELEASE)
	#define SET_DEF_KEY_PARAM_FMT_2_6_38 ", unicast=%d, multicast=%d"
	#define SET_DEF_KEY_PARAM_ARG_2_6_38 , unicast, multicast
#else
	#define SET_DEF_KEY_PARAM_FMT_2_6_38 ""
	#define SET_DEF_KEY_PARAM_ARG_2_6_38
#endif

	RTW_INFO(FUNC_NDEV_FMT
		SET_DEF_KEY_PARAM_FMT
		SET_DEF_KEY_PARAM_FMT_2_6_38
		"\n", FUNC_NDEV_ARG(ndev)
		SET_DEF_KEY_PARAM_ARG
		SET_DEF_KEY_PARAM_ARG_2_6_38
	);

	if ((key_index < WEP_KEYS) && ((psecuritypriv->dot11PrivacyAlgrthm == _WEP40_) || (psecuritypriv->dot11PrivacyAlgrthm == _WEP104_))) { /* set wep default key */
		psecuritypriv->ndisencryptstatus = Ndis802_11Encryption1Enabled;

		psecuritypriv->dot11PrivacyKeyIndex = key_index;

		psecuritypriv->dot11PrivacyAlgrthm = _WEP40_;
		psecuritypriv->dot118021XGrpPrivacy = _WEP40_;
		if (psecuritypriv->dot11DefKeylen[key_index] == 13) {
			psecuritypriv->dot11PrivacyAlgrthm = _WEP104_;
			psecuritypriv->dot118021XGrpPrivacy = _WEP104_;
		}

		psecuritypriv->bWepDefaultKeyIdxSet = 1; /* set the flag to represent that wep default key has been set */
	}

	return 0;

}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30))
int cfg80211_rtw_set_default_mgmt_key(struct wiphy *wiphy,
	struct net_device *ndev,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	int link_id,
#endif
	u8 key_index)
{
#define SET_DEF_KEY_PARAM_FMT " key_index=%d"
#define SET_DEF_KEY_PARAM_ARG , key_index

	RTW_INFO(FUNC_NDEV_FMT
		SET_DEF_KEY_PARAM_FMT
		"\n", FUNC_NDEV_ARG(ndev)
		SET_DEF_KEY_PARAM_ARG
	);

	return 0;
}
#endif

#if defined(CONFIG_GTK_OL) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0))
static int cfg80211_rtw_set_rekey_data(struct wiphy *wiphy,
	struct net_device *ndev,
	struct cfg80211_gtk_rekey_data *data)
{
	/*int i;*/
	struct sta_info *psta;
	_adapter *padapter = (_adapter *)rtw_netdev_priv(ndev);
	struct mlme_priv   *pmlmepriv = &padapter->mlmepriv;
	struct sta_priv *pstapriv = &padapter->stapriv;
	struct security_priv *psecuritypriv = &(padapter->securitypriv);

	psta = rtw_get_stainfo(pstapriv, get_bssid(pmlmepriv));
	if (psta == NULL) {
		RTW_INFO("%s, : Obtain Sta_info fail\n", __func__);
		return -1;
	}

	_rtw_memcpy(psta->kek, data->kek, NL80211_KEK_LEN);
	/*printk("\ncfg80211_rtw_set_rekey_data KEK:");
	for(i=0;i<NL80211_KEK_LEN; i++)
		printk(" %02x ", psta->kek[i]);*/
	_rtw_memcpy(psta->kck, data->kck, NL80211_KCK_LEN);
	/*printk("\ncfg80211_rtw_set_rekey_data KCK:");
	for(i=0;i<NL80211_KCK_LEN; i++)
		printk(" %02x ", psta->kck[i]);*/
	_rtw_memcpy(psta->replay_ctr, data->replay_ctr, NL80211_REPLAY_CTR_LEN);
	psecuritypriv->binstallKCK_KEK = _TRUE;
	/*printk("\nREPLAY_CTR: ");
	for(i=0;i<RTW_REPLAY_CTR_LEN; i++)
		printk(" %02x ", psta->replay_ctr[i]);*/

	return 0;
}
#endif /*CONFIG_GTK_OL*/

#ifdef CONFIG_RTW_MESH
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0))
static enum nl80211_mesh_power_mode rtw_mesh_ps_to_nl80211_mesh_power_mode(u8 ps)
{
	if (ps == RTW_MESH_PS_UNKNOWN)
		return NL80211_MESH_POWER_UNKNOWN;
	if (ps == RTW_MESH_PS_ACTIVE)
		return NL80211_MESH_POWER_ACTIVE;
	if (ps == RTW_MESH_PS_LSLEEP)
		return NL80211_MESH_POWER_LIGHT_SLEEP;
	if (ps == RTW_MESH_PS_DSLEEP)
		return NL80211_MESH_POWER_DEEP_SLEEP;

	rtw_warn_on(1);
	return NL80211_MESH_POWER_UNKNOWN;
}
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
enum nl80211_plink_state rtw_plink_state_to_nl80211_plink_state(u8 plink_state)
{
	if (plink_state == RTW_MESH_PLINK_UNKNOWN)
		return NUM_NL80211_PLINK_STATES;
	if (plink_state == RTW_MESH_PLINK_LISTEN)
		return NL80211_PLINK_LISTEN;
	if (plink_state == RTW_MESH_PLINK_OPN_SNT)
		return NL80211_PLINK_OPN_SNT;
	if (plink_state == RTW_MESH_PLINK_OPN_RCVD)
		return NL80211_PLINK_OPN_RCVD;
	if (plink_state == RTW_MESH_PLINK_CNF_RCVD)
		return NL80211_PLINK_CNF_RCVD;
	if (plink_state == RTW_MESH_PLINK_ESTAB)
		return NL80211_PLINK_ESTAB;
	if (plink_state == RTW_MESH_PLINK_HOLDING)
		return NL80211_PLINK_HOLDING;
	if (plink_state == RTW_MESH_PLINK_BLOCKED)
		return NL80211_PLINK_BLOCKED;

	rtw_warn_on(1);
	return NUM_NL80211_PLINK_STATES;
}

u8 nl80211_plink_state_to_rtw_plink_state(enum nl80211_plink_state plink_state)
{
	if (plink_state == NL80211_PLINK_LISTEN)
		return RTW_MESH_PLINK_LISTEN;
	if (plink_state == NL80211_PLINK_OPN_SNT)
		return RTW_MESH_PLINK_OPN_SNT;
	if (plink_state == NL80211_PLINK_OPN_RCVD)
		return RTW_MESH_PLINK_OPN_RCVD;
	if (plink_state == NL80211_PLINK_CNF_RCVD)
		return RTW_MESH_PLINK_CNF_RCVD;
	if (plink_state == NL80211_PLINK_ESTAB)
		return RTW_MESH_PLINK_ESTAB;
	if (plink_state == NL80211_PLINK_HOLDING)
		return RTW_MESH_PLINK_HOLDING;
	if (plink_state == NL80211_PLINK_BLOCKED)
		return RTW_MESH_PLINK_BLOCKED;

	rtw_warn_on(1);
	return RTW_MESH_PLINK_UNKNOWN;
}
#endif

static void rtw_cfg80211_fill_mesh_only_sta_info(struct mesh_plink_ent *plink, struct sta_info *sta, struct station_info *sinfo)
{
	sinfo->filled |= STATION_INFO_LLID;
	sinfo->llid = plink->llid;
	sinfo->filled |= STATION_INFO_PLID;
	sinfo->plid = plink->plid;
	sinfo->filled |= STATION_INFO_PLINK_STATE;
	sinfo->plink_state = rtw_plink_state_to_nl80211_plink_state(plink->plink_state);
	if (!sta && plink->scanned) {
		sinfo->filled |= STATION_INFO_SIGNAL;
		sinfo->signal = translate_percentage_to_dbm(plink->scanned->network.PhyInfo.SignalStrength);
		sinfo->filled |= STATION_INFO_INACTIVE_TIME;
		if (plink->plink_state == RTW_MESH_PLINK_UNKNOWN)
			sinfo->inactive_time = 0 - 1;
		else
			sinfo->inactive_time = rtw_get_passing_time_ms(plink->scanned->last_scanned);
	}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0))
	if (sta) {
		sinfo->filled |= STATION_INFO_LOCAL_PM;
		sinfo->local_pm = rtw_mesh_ps_to_nl80211_mesh_power_mode(sta->local_mps);
		sinfo->filled |= STATION_INFO_PEER_PM;
		sinfo->peer_pm = rtw_mesh_ps_to_nl80211_mesh_power_mode(sta->peer_mps);
		sinfo->filled |= STATION_INFO_NONPEER_PM;
		sinfo->nonpeer_pm = rtw_mesh_ps_to_nl80211_mesh_power_mode(sta->nonpeer_mps);
	}
#endif
}
#endif /* CONFIG_RTW_MESH */

static int cfg80211_rtw_get_station(struct wiphy *wiphy,
	struct net_device *ndev,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	int link_id,
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0))
	u8 *mac,
#else
	const u8 *mac,
#endif
	struct station_info *sinfo)
{
	int ret = 0;
	_adapter *padapter = (_adapter *)rtw_netdev_priv(ndev);
	struct mlme_priv *pmlmepriv = &padapter->mlmepriv;
	struct sta_info *psta = NULL;
	struct sta_priv *pstapriv = &padapter->stapriv;
#ifdef CONFIG_RTW_MESH
	struct mesh_plink_ent *plink = NULL;
#endif

	sinfo->filled = 0;

	if (!mac) {
		RTW_INFO(FUNC_NDEV_FMT" mac==%p\n", FUNC_NDEV_ARG(ndev), mac);
		ret = -ENOENT;
		goto exit;
	}

	psta = rtw_get_stainfo(pstapriv, mac);
#ifdef CONFIG_RTW_MESH
	if (MLME_IS_MESH(padapter)) {
		if (psta)
			plink = psta->plink;
		if (!plink)
			plink = rtw_mesh_plink_get(padapter, mac);
	}
#endif /* CONFIG_RTW_MESH */

	if ((!MLME_IS_MESH(padapter) && !psta)
		#ifdef CONFIG_RTW_MESH
		|| (MLME_IS_MESH(padapter) && !plink)
		#endif
	) {
		RTW_INFO(FUNC_NDEV_FMT" no sta info for mac="MAC_FMT"\n"
			, FUNC_NDEV_ARG(ndev), MAC_ARG(mac));
		ret = -ENOENT;
		goto exit;
	}

#ifdef CONFIG_DEBUG_CFG80211
	RTW_INFO(FUNC_NDEV_FMT" mac="MAC_FMT"\n", FUNC_NDEV_ARG(ndev), MAC_ARG(mac));
#endif

	/* for infra./P2PClient mode */
	if (check_fwstate(pmlmepriv, WIFI_STATION_STATE)
		&& check_fwstate(pmlmepriv, WIFI_ASOC_STATE)
	) {
		struct wlan_network  *cur_network = &(pmlmepriv->cur_network);

		if (_rtw_memcmp((u8 *)mac, cur_network->network.MacAddress, ETH_ALEN) == _FALSE) {
			RTW_INFO("%s, mismatch bssid="MAC_FMT"\n", __func__, MAC_ARG(cur_network->network.MacAddress));
			ret = -ENOENT;
			goto exit;
		}

		sinfo->filled |= STATION_INFO_SIGNAL;
		sinfo->signal = translate_percentage_to_dbm(padapter->recvpriv.signal_strength);

		sinfo->filled |= STATION_INFO_TX_BITRATE;
		sinfo->txrate.legacy = rtw_get_cur_max_rate(padapter);
	}

	if (psta) {
		if (check_fwstate(pmlmepriv, WIFI_STATION_STATE) == _FALSE
			|| check_fwstate(pmlmepriv, WIFI_ASOC_STATE) == _FALSE
		) {
			sinfo->filled |= STATION_INFO_SIGNAL;
			sinfo->signal = translate_percentage_to_dbm(psta->cmn.rssi_stat.rssi);
		}
		sinfo->filled |= STATION_INFO_INACTIVE_TIME;
		sinfo->inactive_time = rtw_get_passing_time_ms(psta->sta_stats.last_rx_time);
		sinfo->filled |= STATION_INFO_RX_PACKETS;
		sinfo->rx_packets = sta_rx_data_pkts(psta);
		sinfo->filled |= STATION_INFO_TX_PACKETS;
		sinfo->tx_packets = psta->sta_stats.tx_pkts;
		sinfo->filled |= STATION_INFO_TX_FAILED;
		sinfo->tx_failed = psta->sta_stats.tx_fail_cnt;
	}

#ifdef CONFIG_RTW_MESH
	if (MLME_IS_MESH(padapter))
		rtw_cfg80211_fill_mesh_only_sta_info(plink, psta, sinfo);
#endif

exit:
	return ret;
}

extern int netdev_open(struct net_device *pnetdev);

#if 0
enum nl80211_iftype {
	NL80211_IFTYPE_UNSPECIFIED,
	NL80211_IFTYPE_ADHOC, /* 1 */
	NL80211_IFTYPE_STATION, /* 2 */
	NL80211_IFTYPE_AP, /* 3 */
	NL80211_IFTYPE_AP_VLAN,
	NL80211_IFTYPE_WDS,
	NL80211_IFTYPE_MONITOR, /* 6 */
	NL80211_IFTYPE_MESH_POINT,
	NL80211_IFTYPE_P2P_CLIENT, /* 8 */
	NL80211_IFTYPE_P2P_GO, /* 9 */
	/* keep last */
	NUM_NL80211_IFTYPES,
	NL80211_IFTYPE_MAX = NUM_NL80211_IFTYPES - 1
};
#endif
static int cfg80211_rtw_change_iface(struct wiphy *wiphy,
				     struct net_device *ndev,
				     enum nl80211_iftype type,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0))
				     u32 *flags,
#endif
				     struct vif_params *params)
{
	enum nl80211_iftype old_type;
	NDIS_802_11_NETWORK_INFRASTRUCTURE networkType;
	_adapter *padapter = (_adapter *)rtw_netdev_priv(ndev);
	struct wireless_dev *rtw_wdev = padapter->rtw_wdev;
	struct mlme_ext_priv	*pmlmeext = &(padapter->mlmeextpriv);
#ifdef CONFIG_P2P
	struct wifidirect_info *pwdinfo = &(padapter->wdinfo);
#endif
#ifdef CONFIG_MONITOR_MODE_XMIT
	struct mlme_priv	*pmlmepriv = &(padapter->mlmepriv);
#endif
	int ret = 0;
	u8 change = _FALSE;

	RTW_INFO(FUNC_NDEV_FMT" type=%d, hw_port:%d\n", FUNC_NDEV_ARG(ndev), type, padapter->hw_port);

	if (adapter_to_dvobj(padapter)->processing_dev_remove == _TRUE) {
		ret = -EPERM;
		goto exit;
	}


	RTW_INFO(FUNC_NDEV_FMT" call netdev_open\n", FUNC_NDEV_ARG(ndev));
	if (netdev_open(ndev) != 0) {
		RTW_INFO(FUNC_NDEV_FMT" call netdev_open fail\n", FUNC_NDEV_ARG(ndev));
		ret = -EPERM;
		goto exit;
	}


	if (_FAIL == rtw_pwr_wakeup(padapter)) {
		RTW_INFO(FUNC_NDEV_FMT" call rtw_pwr_wakeup fail\n", FUNC_NDEV_ARG(ndev));
		ret = -EPERM;
		goto exit;
	}

	old_type = rtw_wdev->iftype;
	RTW_INFO(FUNC_NDEV_FMT" old_iftype=%d, new_iftype=%d\n",
		FUNC_NDEV_ARG(ndev), old_type, type);

	if (old_type != type) {
		change = _TRUE;
		pmlmeext->action_public_rxseq = 0xffff;
		pmlmeext->action_public_dialog_token = 0xff;
	}

	/* initial default type */
	ndev->type = ARPHRD_ETHER;

	/*
	 * Disable Power Save in moniter mode,
	 * and enable it after leaving moniter mode.
	 */
	if (type == NL80211_IFTYPE_MONITOR) {
		rtw_ps_deny(padapter, PS_DENY_MONITOR_MODE);
		LeaveAllPowerSaveMode(padapter);
	} else if (old_type == NL80211_IFTYPE_MONITOR) {
		/* driver in moniter mode in last time */
		rtw_ps_deny_cancel(padapter, PS_DENY_MONITOR_MODE);
	}

	switch (type) {
	case NL80211_IFTYPE_ADHOC:
		networkType = Ndis802_11IBSS;
		break;

	case NL80211_IFTYPE_STATION:
		networkType = Ndis802_11Infrastructure;
		#ifdef CONFIG_P2P
		if (change && pwdinfo->driver_interface == DRIVER_CFG80211) {
			#if !RTW_P2P_GROUP_INTERFACE
			if (rtw_p2p_chk_role(pwdinfo, P2P_ROLE_CLIENT)
				|| rtw_p2p_chk_role(pwdinfo, P2P_ROLE_GO)
			) {
				/* it means remove GC/GO and change mode from GC/GO to station(P2P DEVICE) */
				rtw_p2p_set_role(pwdinfo, P2P_ROLE_DEVICE);
			}
			#endif
		}
		#endif /* CONFIG_P2P */
		break;

	case NL80211_IFTYPE_AP:
		networkType = Ndis802_11APMode;
		#ifdef CONFIG_P2P
		if (change && pwdinfo->driver_interface == DRIVER_CFG80211) {
			#if !RTW_P2P_GROUP_INTERFACE
			if (!rtw_p2p_chk_state(pwdinfo, P2P_STATE_NONE)) {
				/* it means P2P Group created, we will be GO and change mode from  P2P DEVICE to AP(GO) */
				rtw_p2p_set_role(pwdinfo, P2P_ROLE_GO);
			}
			#endif
		}
		#endif /* CONFIG_P2P */
		break;

#if defined(CONFIG_P2P) && ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE))
	case NL80211_IFTYPE_P2P_CLIENT:
		networkType = Ndis802_11Infrastructure;
		if (change && pwdinfo->driver_interface == DRIVER_CFG80211) {
			if (!rtw_p2p_enable(padapter, P2P_ROLE_CLIENT)) {
				ret = -EOPNOTSUPP;
				goto exit;
			}
		}
		break;

	case NL80211_IFTYPE_P2P_GO:
		networkType = Ndis802_11APMode;
		if (change && pwdinfo->driver_interface == DRIVER_CFG80211) {
			if (!rtw_p2p_enable(padapter, P2P_ROLE_GO)) {
				ret = -EOPNOTSUPP;
				goto exit;
			}
		}
		break;
#endif /* defined(CONFIG_P2P) && ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE)) */

#ifdef CONFIG_RTW_MESH
	case NL80211_IFTYPE_MESH_POINT:
		networkType = Ndis802_11_mesh;
		break;
#endif

#ifdef CONFIG_WIFI_MONITOR
	case NL80211_IFTYPE_MONITOR:
		networkType = Ndis802_11Monitor;

#ifdef CONFIG_CUSTOMER_ALIBABA_GENERAL
		ndev->type = ARPHRD_IEEE80211; /* IEEE 802.11 : 801 */
#else
		ndev->type = ARPHRD_IEEE80211_RADIOTAP; /* IEEE 802.11 + radiotap header : 803 */
#endif
		break;
#endif /* CONFIG_WIFI_MONITOR */
	default:
		ret = -EOPNOTSUPP;
		goto exit;
	}

	rtw_wdev->iftype = type;

	if (rtw_set_802_11_infrastructure_mode(padapter, networkType, 0) == _FALSE) {
		rtw_wdev->iftype = old_type;
		ret = -EPERM;
		goto exit;
	}

	rtw_setopmode_cmd(padapter, networkType, RTW_CMDF_WAIT_ACK);
#ifdef CONFIG_MONITOR_MODE_XMIT
	if (check_fwstate(pmlmepriv, WIFI_MONITOR_STATE) == _TRUE)
		rtw_indicate_connect(padapter);
#endif

	#if defined(CONFIG_RTW_WDS) && (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33))
	if (params->use_4addr != -1) {
		RTW_INFO(FUNC_NDEV_FMT" use_4addr=%d\n"
			, FUNC_NDEV_ARG(ndev), params->use_4addr);
		adapter_set_use_wds(padapter, params->use_4addr);
	}
	#endif

exit:

	RTW_INFO(FUNC_NDEV_FMT" ret:%d\n", FUNC_NDEV_ARG(ndev), ret);
	return ret;
}

void rtw_cfg80211_indicate_scan_done(_adapter *adapter, bool aborted)
{
	struct rtw_wdev_priv *pwdev_priv = adapter_wdev_data(adapter);
	_irqL	irqL;

#if (KERNEL_VERSION(4, 8, 0) <= LINUX_VERSION_CODE)
	struct cfg80211_scan_info info;

	memset(&info, 0, sizeof(info));
	info.aborted = aborted;
#endif

	_enter_critical_bh(&pwdev_priv->scan_req_lock, &irqL);
	if (pwdev_priv->scan_request != NULL) {
		#ifdef CONFIG_DEBUG_CFG80211
		RTW_INFO("%s with scan req\n", __FUNCTION__);
		#endif

		/* avoid WARN_ON(request != wiphy_to_dev(request->wiphy)->scan_req); */
		if (pwdev_priv->scan_request->wiphy != pwdev_priv->rtw_wdev->wiphy)
			RTW_INFO("error wiphy compare\n");
		else
#if (KERNEL_VERSION(4, 8, 0) <= LINUX_VERSION_CODE)
			cfg80211_scan_done(pwdev_priv->scan_request, &info);
#else
			cfg80211_scan_done(pwdev_priv->scan_request, aborted);
#endif

		pwdev_priv->scan_request = NULL;
	} else {
		#ifdef CONFIG_DEBUG_CFG80211
		RTW_INFO("%s without scan req\n", __FUNCTION__);
		#endif
	}
	_exit_critical_bh(&pwdev_priv->scan_req_lock, &irqL);
}

u32 rtw_cfg80211_wait_scan_req_empty(_adapter *adapter, u32 timeout_ms)
{
	struct rtw_wdev_priv *wdev_priv = adapter_wdev_data(adapter);
	u8 empty = _FALSE;
	systime start;
	u32 pass_ms;

	start = rtw_get_current_time();

	while (rtw_get_passing_time_ms(start) <= timeout_ms) {

		if (RTW_CANNOT_RUN(adapter))
			break;

		if (!wdev_priv->scan_request) {
			empty = _TRUE;
			break;
		}

		rtw_msleep_os(10);
	}

	pass_ms = rtw_get_passing_time_ms(start);

	if (empty == _FALSE && pass_ms > timeout_ms) {
		RTW_PRINT(FUNC_ADPT_FMT" pass_ms:%u, timeout\n"
			, FUNC_ADPT_ARG(adapter), pass_ms);
		rtw_cfg80211_indicate_scan_done(adapter, _TRUE);
	}

	return pass_ms;
}

void rtw_cfg80211_unlink_bss(_adapter *padapter, struct wlan_network *pnetwork)
{
	struct wireless_dev *pwdev = padapter->rtw_wdev;
	struct wiphy *wiphy = pwdev->wiphy;
	struct cfg80211_bss *bss = NULL;
	WLAN_BSSID_EX select_network = pnetwork->network;

	bss = cfg80211_get_bss(wiphy, NULL/*notify_channel*/,
		select_network.MacAddress, select_network.Ssid.Ssid,
		select_network.Ssid.SsidLength,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
		select_network.InfrastructureMode == Ndis802_11Infrastructure?IEEE80211_BSS_TYPE_ESS:IEEE80211_BSS_TYPE_IBSS,
		IEEE80211_PRIVACY(select_network.Privacy));
#else
		select_network.InfrastructureMode == Ndis802_11Infrastructure?WLAN_CAPABILITY_ESS:WLAN_CAPABILITY_IBSS,
		select_network.InfrastructureMode == Ndis802_11Infrastructure?WLAN_CAPABILITY_ESS:WLAN_CAPABILITY_IBSS);
#endif

	if (bss) {
		cfg80211_unlink_bss(wiphy, bss);
		RTW_INFO("%s(): cfg80211_unlink %s!!\n", __func__, select_network.Ssid.Ssid);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
		cfg80211_put_bss(padapter->rtw_wdev->wiphy, bss);
#else
		cfg80211_put_bss(bss);
#endif
	}
	return;
}

/* if target wps scan ongoing, target_ssid is filled */
int rtw_cfg80211_is_target_wps_scan(struct cfg80211_scan_request *scan_req, struct cfg80211_ssid *target_ssid)
{
	int ret = 0;

	if (scan_req->n_ssids != 1
		|| scan_req->ssids[0].ssid_len == 0
		|| scan_req->n_channels != 1
	)
		goto exit;

	/* under target WPS scan */
	_rtw_memcpy(target_ssid, scan_req->ssids, sizeof(struct cfg80211_ssid));
	ret = 1;

exit:
	return ret;
}

static void _rtw_cfg80211_surveydone_event_callback(_adapter *padapter, struct cfg80211_scan_request *scan_req)
{
	struct rf_ctl_t *rfctl = adapter_to_rfctl(padapter);
	RT_CHANNEL_INFO *chset = rfctl->channel_set;
	_irqL	irqL;
	_list					*plist, *phead;
	struct	mlme_priv	*pmlmepriv = &(padapter->mlmepriv);
	_queue				*queue	= &(pmlmepriv->scanned_queue);
	struct	wlan_network	*pnetwork = NULL;
	struct rtw_wdev_priv *pwdev_priv = adapter_wdev_data(padapter);
	struct cfg80211_ssid target_ssid;
	u8 target_wps_scan = 0;
	u8 ch;

#ifdef CONFIG_DEBUG_CFG80211
	RTW_INFO("%s\n", __func__);
#endif

	if (scan_req)
		target_wps_scan = rtw_cfg80211_is_target_wps_scan(scan_req, &target_ssid);
	else {
		_enter_critical_bh(&pwdev_priv->scan_req_lock, &irqL);
		if (pwdev_priv->scan_request != NULL)
			target_wps_scan = rtw_cfg80211_is_target_wps_scan(pwdev_priv->scan_request, &target_ssid);
		_exit_critical_bh(&pwdev_priv->scan_req_lock, &irqL);
	}

	_enter_critical_bh(&(pmlmepriv->scanned_queue.lock), &irqL);

	phead = get_list_head(queue);
	plist = get_next(phead);

	while (1) {
		if (rtw_end_of_queue_search(phead, plist) == _TRUE)
			break;

		pnetwork = LIST_CONTAINOR(plist, struct wlan_network, list);
		ch = pnetwork->network.Configuration.DSConfig;

		/* report network only if the current channel set contains the channel to which this network belongs */
		if (rtw_chset_search_ch(chset, ch) >= 0
			&& rtw_mlme_band_check(padapter, ch) == _TRUE
			&& _TRUE == rtw_validate_ssid(&(pnetwork->network.Ssid))
			&& (!IS_DFS_SLAVE_WITH_RD(rfctl)
				|| rtw_rfctl_dfs_domain_unknown(rfctl)
				|| !rtw_chset_is_ch_non_ocp(chset, ch))
		) {
			if (target_wps_scan)
				rtw_cfg80211_clear_wps_sr_of_non_target_bss(padapter, pnetwork, &target_ssid);
			rtw_cfg80211_inform_bss(padapter, pnetwork);
		}
#if 0
		/* check ralink testbed RSN IE length */
		{
			if (_rtw_memcmp(pnetwork->network.Ssid.Ssid, "Ralink_11n_AP", 13)) {
				uint ie_len = 0;
				u8 *p = NULL;
				p = rtw_get_ie(pnetwork->network.IEs + _BEACON_IE_OFFSET_, _RSN_IE_2_, &ie_len, (pnetwork->network.IELength - _BEACON_IE_OFFSET_));
				RTW_INFO("ie_len=%d\n", ie_len);
			}
		}
#endif
		plist = get_next(plist);

	}

	_exit_critical_bh(&(pmlmepriv->scanned_queue.lock), &irqL);
}

inline void rtw_cfg80211_surveydone_event_callback(_adapter *padapter)
{
	_rtw_cfg80211_surveydone_event_callback(padapter, NULL);
}

static int rtw_cfg80211_set_probe_req_wpsp2pie(_adapter *padapter, char *buf, int len)
{
	int ret = 0;
	uint wps_ielen = 0;
	u8 *wps_ie;
	u32	p2p_ielen = 0;
	u8 *p2p_ie;
	u32	wfd_ielen = 0;
	u8 *wfd_ie;
	struct mlme_priv *pmlmepriv = &(padapter->mlmepriv);

#ifdef CONFIG_DEBUG_CFG80211
	RTW_INFO("%s, ielen=%d\n", __func__, len);
#endif

	if (len > 0) {
		wps_ie = rtw_get_wps_ie(buf, len, NULL, &wps_ielen);
		if (wps_ie) {
			#ifdef CONFIG_DEBUG_CFG80211
			RTW_INFO("probe_req_wps_ielen=%d\n", wps_ielen);
			#endif

			if (pmlmepriv->wps_probe_req_ie) {
				u32 free_len = pmlmepriv->wps_probe_req_ie_len;
				pmlmepriv->wps_probe_req_ie_len = 0;
				rtw_mfree(pmlmepriv->wps_probe_req_ie, free_len);
				pmlmepriv->wps_probe_req_ie = NULL;
			}

			pmlmepriv->wps_probe_req_ie = rtw_malloc(wps_ielen);
			if (pmlmepriv->wps_probe_req_ie == NULL) {
				RTW_INFO("%s()-%d: rtw_malloc() ERROR!\n", __FUNCTION__, __LINE__);
				return -EINVAL;

			}
			_rtw_memcpy(pmlmepriv->wps_probe_req_ie, wps_ie, wps_ielen);
			pmlmepriv->wps_probe_req_ie_len = wps_ielen;
		}

		/* buf += wps_ielen; */
		/* len -= wps_ielen; */

		#ifdef CONFIG_P2P
		p2p_ie = rtw_get_p2p_ie(buf, len, NULL, &p2p_ielen);
		if (p2p_ie) {
			struct wifidirect_info *wdinfo = &padapter->wdinfo;
			u32 attr_contentlen = 0;
			u8 listen_ch_attr[5];

			#ifdef CONFIG_DEBUG_CFG80211
			RTW_INFO("probe_req_p2p_ielen=%d\n", p2p_ielen);
			#endif

			if (pmlmepriv->p2p_probe_req_ie) {
				u32 free_len = pmlmepriv->p2p_probe_req_ie_len;
				pmlmepriv->p2p_probe_req_ie_len = 0;
				rtw_mfree(pmlmepriv->p2p_probe_req_ie, free_len);
				pmlmepriv->p2p_probe_req_ie = NULL;
			}

			pmlmepriv->p2p_probe_req_ie = rtw_malloc(p2p_ielen);
			if (pmlmepriv->p2p_probe_req_ie == NULL) {
				RTW_INFO("%s()-%d: rtw_malloc() ERROR!\n", __FUNCTION__, __LINE__);
				return -EINVAL;

			}
			_rtw_memcpy(pmlmepriv->p2p_probe_req_ie, p2p_ie, p2p_ielen);
			pmlmepriv->p2p_probe_req_ie_len = p2p_ielen;

			attr_contentlen = sizeof(listen_ch_attr);
			if (rtw_get_p2p_attr_content(p2p_ie, p2p_ielen, P2P_ATTR_LISTEN_CH, (u8 *)listen_ch_attr, (uint *) &attr_contentlen)) {
				if (wdinfo->listen_channel !=  listen_ch_attr[4]) {
					RTW_INFO(FUNC_ADPT_FMT" listen channel - country:%c%c%c, class:%u, ch:%u\n",
						FUNC_ADPT_ARG(padapter), listen_ch_attr[0], listen_ch_attr[1], listen_ch_attr[2],
						listen_ch_attr[3], listen_ch_attr[4]);
					wdinfo->listen_channel = listen_ch_attr[4];
				}
			}
		}
		#endif /* CONFIG_P2P */

		#ifdef CONFIG_WFD
		wfd_ie = rtw_get_wfd_ie(buf, len, NULL, &wfd_ielen);
		if (wfd_ie) {
			#ifdef CONFIG_DEBUG_CFG80211
			RTW_INFO("probe_req_wfd_ielen=%d\n", wfd_ielen);
			#endif

			if (rtw_mlme_update_wfd_ie_data(pmlmepriv, MLME_PROBE_REQ_IE, wfd_ie, wfd_ielen) != _SUCCESS)
				return -EINVAL;
		}
		#endif /* CONFIG_WFD */

		#ifdef CONFIG_RTW_MBO
		rtw_mbo_update_ie_data(padapter, buf, len);
		#endif
	}

	return ret;

}

#ifdef CONFIG_CONCURRENT_MODE
u8 rtw_cfg80211_scan_via_buddy(_adapter *padapter, struct cfg80211_scan_request *request)
{
	int i;
	u8 ret = _FALSE;
	_adapter *iface = NULL;
	_irqL	irqL;
	struct dvobj_priv *dvobj = adapter_to_dvobj(padapter);
	struct rtw_wdev_priv *pwdev_priv = adapter_wdev_data(padapter);
	struct mlme_priv *pmlmepriv = &padapter->mlmepriv;

	for (i = 0; i < dvobj->iface_nums; i++) {
		struct mlme_priv *buddy_mlmepriv;
		struct rtw_wdev_priv *buddy_wdev_priv;

		iface = dvobj->padapters[i];
		if (iface == NULL)
			continue;

		if (iface == padapter)
			continue;

		if (rtw_is_adapter_up(iface) == _FALSE)
			continue;

		buddy_mlmepriv = &iface->mlmepriv;
		if (!check_fwstate(buddy_mlmepriv, WIFI_UNDER_SURVEY))
			continue;

		buddy_wdev_priv = adapter_wdev_data(iface);
		_enter_critical_bh(&pwdev_priv->scan_req_lock, &irqL);
		_enter_critical_bh(&buddy_wdev_priv->scan_req_lock, &irqL);
		if (buddy_wdev_priv->scan_request) {
			pmlmepriv->scanning_via_buddy_intf = _TRUE;
			_enter_critical_bh(&pmlmepriv->lock, &irqL);
			set_fwstate(pmlmepriv, WIFI_UNDER_SURVEY);
			_exit_critical_bh(&pmlmepriv->lock, &irqL);
			pwdev_priv->scan_request = request;
			ret = _TRUE;
		}
		_exit_critical_bh(&buddy_wdev_priv->scan_req_lock, &irqL);
		_exit_critical_bh(&pwdev_priv->scan_req_lock, &irqL);

		if (ret == _TRUE)
			goto exit;
	}

exit:
	return ret;
}

void rtw_cfg80211_indicate_scan_done_for_buddy(_adapter *padapter, bool bscan_aborted)
{
	int i;
	_adapter *iface = NULL;
	_irqL	irqL;
	struct dvobj_priv *dvobj = adapter_to_dvobj(padapter);
	struct mlme_priv *mlmepriv;
	struct rtw_wdev_priv *wdev_priv;
	bool indicate_buddy_scan;

	for (i = 0; i < dvobj->iface_nums; i++) {
		iface = dvobj->padapters[i];
		if ((iface) && rtw_is_adapter_up(iface)) {

			if (iface == padapter)
				continue;

			mlmepriv = &(iface->mlmepriv);
			wdev_priv = adapter_wdev_data(iface);

			indicate_buddy_scan = _FALSE;
			_enter_critical_bh(&wdev_priv->scan_req_lock, &irqL);
			if (mlmepriv->scanning_via_buddy_intf == _TRUE) {
				mlmepriv->scanning_via_buddy_intf = _FALSE;
				clr_fwstate(mlmepriv, WIFI_UNDER_SURVEY);
				if (wdev_priv->scan_request)
					indicate_buddy_scan = _TRUE;
			}
			_exit_critical_bh(&wdev_priv->scan_req_lock, &irqL);

			if (indicate_buddy_scan == _TRUE) {
				rtw_cfg80211_surveydone_event_callback(iface);
				rtw_indicate_scan_done(iface, bscan_aborted);
			}

		}
	}
}
#endif /* CONFIG_CONCURRENT_MODE */

static int cfg80211_rtw_scan(struct wiphy *wiphy
	#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 6, 0))
	, struct net_device *ndev
	#endif
	, struct cfg80211_scan_request *request)
{
	int i;
	u8 _status = _FALSE;
	int ret = 0;
	struct sitesurvey_parm parm;
	_irqL	irqL;
	u8 survey_times = 3;
	u8 survey_times_for_one_ch = 6;
	struct cfg80211_ssid *ssids = request->ssids;
	int social_channel = 0, j = 0;
	bool need_indicate_scan_done = _FALSE;
	bool ps_denied = _FALSE;
	u8 ssc_chk;
	_adapter *padapter;
	struct wireless_dev *wdev;
	struct rtw_wdev_priv *pwdev_priv;
	struct mlme_priv *pmlmepriv = NULL;
#ifdef CONFIG_P2P
	struct wifidirect_info *pwdinfo;
#endif /* CONFIG_P2P */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0))
	wdev = request->wdev;
	#if defined(RTW_DEDICATED_P2P_DEVICE)
	if (wdev == wiphy_to_pd_wdev(wiphy))
		padapter = wiphy_to_adapter(wiphy);
	else
	#endif
	if (wdev_to_ndev(wdev))
		padapter = (_adapter *)rtw_netdev_priv(wdev_to_ndev(wdev));
	else {
		ret = -EINVAL;
		goto exit;
	}
#else
	if (ndev == NULL) {
		ret = -EINVAL;
		goto exit;
	}
	padapter = (_adapter *)rtw_netdev_priv(ndev);
	wdev = ndev_to_wdev(ndev);
#endif

	pwdev_priv = adapter_wdev_data(padapter);
	pmlmepriv = &padapter->mlmepriv;
#ifdef CONFIG_P2P
	pwdinfo = &(padapter->wdinfo);
#endif /* CONFIG_P2P */

	RTW_INFO(FUNC_ADPT_FMT"%s\n", FUNC_ADPT_ARG(padapter)
		, wdev == wiphy_to_pd_wdev(wiphy) ? " PD" : "");

#ifdef CONFIG_RTW_SCAN_RAND
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0))
	if (request->flags & NL80211_SCAN_FLAG_RANDOM_ADDR) {
		get_random_mask_addr(pwdev_priv->pno_mac_addr, request->mac_addr,
				     request->mac_addr_mask);
		print_hex_dump(KERN_DEBUG, "random mac_addr: ", 
			DUMP_PREFIX_OFFSET, 16, 1, pwdev_priv->pno_mac_addr, ETH_ALEN, 1);
	}
	else
		memset(pwdev_priv->pno_mac_addr, 0xFF, ETH_ALEN);

#endif
#endif


#if 1
	ssc_chk = rtw_sitesurvey_condition_check(padapter, _TRUE);

	if (ssc_chk == SS_DENY_MP_MODE)
		goto bypass_p2p_chk;
#ifdef DBG_LA_MODE
	if (ssc_chk == SS_DENY_LA_MODE)
		goto bypass_p2p_chk;
#endif
#ifdef CONFIG_P2P
	if (pwdinfo->driver_interface == DRIVER_CFG80211) {
		if (request->n_ssids && ssids
			&& _rtw_memcmp(ssids[0].ssid, "DIRECT-", 7)
			&& rtw_get_p2p_ie((u8 *)request->ie, request->ie_len, NULL, NULL)
		) {
			if (rtw_p2p_chk_state(pwdinfo, P2P_STATE_NONE)) {
				if (!rtw_p2p_enable(padapter, P2P_ROLE_DEVICE)) {
					ret = -EOPNOTSUPP;
					goto exit;
				}
			} else {
				rtw_p2p_set_pre_state(pwdinfo, rtw_p2p_state(pwdinfo));
				#ifdef CONFIG_DEBUG_CFG80211
				RTW_INFO("%s, role=%d, p2p_state=%d\n", __func__, rtw_p2p_role(pwdinfo), rtw_p2p_state(pwdinfo));
				#endif
			}
			rtw_p2p_set_state(pwdinfo, P2P_STATE_LISTEN);

			if (request->n_channels == 3 &&
				request->channels[0]->hw_value == 1 &&
				request->channels[1]->hw_value == 6 &&
				request->channels[2]->hw_value == 11
			)
				social_channel = 1;
		}
	}
#endif /*CONFIG_P2P*/

	if (request->ie && request->ie_len > 0)
		rtw_cfg80211_set_probe_req_wpsp2pie(padapter, (u8 *)request->ie, request->ie_len);

bypass_p2p_chk:

	switch (ssc_chk) {
		case SS_ALLOW :
			break;

		case SS_DENY_MP_MODE:
			ret = -EPERM;
			goto exit;
		#ifdef DBG_LA_MODE
		case SS_DENY_LA_MODE:
			ret = -EPERM;
			goto exit;
		#endif
		#ifdef CONFIG_RTW_REPEATER_SON
		case SS_DENY_RSON_SCANING :
		#endif
		case SS_DENY_BLOCK_SCAN :
		case SS_DENY_SELF_AP_UNDER_WPS :
		case SS_DENY_SELF_AP_UNDER_LINKING :
		case SS_DENY_SELF_AP_UNDER_SURVEY :
		case SS_DENY_SELF_STA_UNDER_SURVEY :
		#ifdef CONFIG_CONCURRENT_MODE
		case SS_DENY_BUDDY_UNDER_LINK_WPS :
		#endif
		case SS_DENY_BUSY_TRAFFIC :
		case SS_DENY_ADAPTIVITY:
			need_indicate_scan_done = _TRUE;
			goto check_need_indicate_scan_done;

		case SS_DENY_BY_DRV :
			#ifdef CONFIG_NOTIFY_SCAN_ABORT_WITH_BUSY
			ret = -EBUSY;
			goto exit;
			#else
			need_indicate_scan_done = _TRUE;
			goto check_need_indicate_scan_done;
			#endif
			break;

		case SS_DENY_SELF_STA_UNDER_LINKING :
			ret = -EBUSY;
			goto check_need_indicate_scan_done;

		#ifdef CONFIG_CONCURRENT_MODE
		case SS_DENY_BUDDY_UNDER_SURVEY :
			{
				bool scan_via_buddy = rtw_cfg80211_scan_via_buddy(padapter, request);

				if (scan_via_buddy == _FALSE)
					need_indicate_scan_done = _TRUE;

				goto check_need_indicate_scan_done;
			}
		#endif

		default :
			RTW_ERR("site survey check code (%d) unknown\n", ssc_chk);
			need_indicate_scan_done = _TRUE;
			goto check_need_indicate_scan_done;
	}

	rtw_ps_deny(padapter, PS_DENY_SCAN);
	ps_denied = _TRUE;
	if (_FAIL == rtw_pwr_wakeup(padapter)) {
		need_indicate_scan_done = _TRUE;
		goto check_need_indicate_scan_done;
	}

#else


#ifdef CONFIG_MP_INCLUDED
	if (rtw_mp_mode_check(padapter)) {
		RTW_INFO("MP mode block Scan request\n");
		ret = -EPERM;
		goto exit;
	}
#endif

#ifdef CONFIG_P2P
	if (pwdinfo->driver_interface == DRIVER_CFG80211) {
		if (request->n_ssids && ssids
			&& _rtw_memcmp(ssids[0].ssid, "DIRECT-", 7)
			&& rtw_get_p2p_ie((u8 *)request->ie, request->ie_len, NULL, NULL)
		) {
			if (rtw_p2p_chk_state(pwdinfo, P2P_STATE_NONE))
				rtw_p2p_enable(padapter, P2P_ROLE_DEVICE);
			else {
				rtw_p2p_set_pre_state(pwdinfo, rtw_p2p_state(pwdinfo));
				#ifdef CONFIG_DEBUG_CFG80211
				RTW_INFO("%s, role=%d, p2p_state=%d\n", __func__, rtw_p2p_role(pwdinfo), rtw_p2p_state(pwdinfo));
				#endif
			}
			rtw_p2p_set_state(pwdinfo, P2P_STATE_LISTEN);

			if (request->n_channels == 3 &&
				request->channels[0]->hw_value == 1 &&
				request->channels[1]->hw_value == 6 &&
				request->channels[2]->hw_value == 11
			)
				social_channel = 1;
		}
	}
#endif /*CONFIG_P2P*/

	if (request->ie && request->ie_len > 0)
		rtw_cfg80211_set_probe_req_wpsp2pie(padapter, (u8 *)request->ie, request->ie_len);

#ifdef CONFIG_RTW_REPEATER_SON
	if (padapter->rtw_rson_scanstage == RSON_SCAN_PROCESS) {
		RTW_INFO(FUNC_ADPT_FMT" blocking scan for under rson scanning process\n", FUNC_ADPT_ARG(padapter));
		need_indicate_scan_done = _TRUE;
		goto check_need_indicate_scan_done;
	}
#endif

	if (adapter_wdev_data(padapter)->block_scan == _TRUE) {
		RTW_INFO(FUNC_ADPT_FMT" wdev_priv.block_scan is set\n", FUNC_ADPT_ARG(padapter));
		need_indicate_scan_done = _TRUE;
		goto check_need_indicate_scan_done;
	}

	rtw_ps_deny(padapter, PS_DENY_SCAN);
	ps_denied = _TRUE;
	if (_FAIL == rtw_pwr_wakeup(padapter)) {
		need_indicate_scan_done = _TRUE;
		goto check_need_indicate_scan_done;
	}

	if (rtw_is_scan_deny(padapter)) {
		RTW_INFO(FUNC_ADPT_FMT	": scan deny\n", FUNC_ADPT_ARG(padapter));
#ifdef CONFIG_NOTIFY_SCAN_ABORT_WITH_BUSY
		ret = -EBUSY;
		goto exit;
#else
		need_indicate_scan_done = _TRUE;
		goto check_need_indicate_scan_done;
#endif
	}

	/* check fw state*/
	if (check_fwstate(pmlmepriv, WIFI_AP_STATE) == _TRUE) {

#ifdef CONFIG_DEBUG_CFG80211
		RTW_INFO(FUNC_ADPT_FMT" under WIFI_AP_STATE\n", FUNC_ADPT_ARG(padapter));
#endif

		if (check_fwstate(pmlmepriv, WIFI_UNDER_WPS | WIFI_UNDER_SURVEY | WIFI_UNDER_LINKING) == _TRUE) {
			RTW_INFO("%s, fwstate=0x%x\n", __func__, pmlmepriv->fw_state);

			if (check_fwstate(pmlmepriv, WIFI_UNDER_WPS))
				RTW_INFO("AP mode process WPS\n");

			need_indicate_scan_done = _TRUE;
			goto check_need_indicate_scan_done;
		}
	}

	if (check_fwstate(pmlmepriv, WIFI_UNDER_SURVEY) == _TRUE) {
		RTW_INFO("%s, fwstate=0x%x\n", __func__, pmlmepriv->fw_state);
		need_indicate_scan_done = _TRUE;
		goto check_need_indicate_scan_done;
	} else if (check_fwstate(pmlmepriv, WIFI_UNDER_LINKING) == _TRUE) {
		RTW_INFO("%s, fwstate=0x%x\n", __func__, pmlmepriv->fw_state);
		ret = -EBUSY;
		goto check_need_indicate_scan_done;
	}

#ifdef CONFIG_CONCURRENT_MODE
	if (rtw_mi_buddy_check_fwstate(padapter, WIFI_UNDER_LINKING | WIFI_UNDER_WPS)) {
		RTW_INFO("%s exit due to buddy_intf's mlme state under linking or wps\n", __func__);
		need_indicate_scan_done = _TRUE;
		goto check_need_indicate_scan_done;

	} else if (rtw_mi_buddy_check_fwstate(padapter, WIFI_UNDER_SURVEY)) {
		bool scan_via_buddy = rtw_cfg80211_scan_via_buddy(padapter, request);

		if (scan_via_buddy == _FALSE)
			need_indicate_scan_done = _TRUE;

		goto check_need_indicate_scan_done;
	}
#endif /* CONFIG_CONCURRENT_MODE */

#ifdef RTW_BUSY_DENY_SCAN
	/*
	 * busy traffic check
	 * Rules:
	 * 1. If (scan interval <= BUSY_TRAFFIC_SCAN_DENY_PERIOD) always allow
	 *    scan, otherwise goto rule 2.
	 * 2. Deny scan if any interface is busy, otherwise allow scan.
	 */
	if (pmlmepriv->lastscantime
	    && (rtw_get_passing_time_ms(pmlmepriv->lastscantime) >
		registry_par->scan_interval_thr)
	    && rtw_mi_busy_traffic_check(padapter)) {
		RTW_WARN(FUNC_ADPT_FMT ": scan abort!! BusyTraffic\n",
			 FUNC_ADPT_ARG(padapter));
 		need_indicate_scan_done = _TRUE;
		goto check_need_indicate_scan_done;
	}
#endif /* RTW_BUSY_DENY_SCAN */
#endif

#ifdef CONFIG_P2P
	if (!rtw_p2p_chk_state(pwdinfo, P2P_STATE_NONE) && !rtw_p2p_chk_state(pwdinfo, P2P_STATE_IDLE)) {
		rtw_p2p_set_state(pwdinfo, P2P_STATE_FIND_PHASE_SEARCH);

		if (social_channel == 0)
			rtw_p2p_findphase_ex_set(pwdinfo, P2P_FINDPHASE_EX_NONE);
		else
			rtw_p2p_findphase_ex_set(pwdinfo, P2P_FINDPHASE_EX_SOCIAL_LAST);
	}
#endif /* CONFIG_P2P */

	rtw_init_sitesurvey_parm(padapter, &parm);

	/* parsing request ssids, n_ssids */
	for (i = 0; i < request->n_ssids && ssids && i < RTW_SSID_SCAN_AMOUNT; i++) {
		#ifdef CONFIG_DEBUG_CFG80211
		RTW_INFO("ssid=%s, len=%d\n", ssids[i].ssid, ssids[i].ssid_len);
		#endif
		_rtw_memcpy(&parm.ssid[i].Ssid, ssids[i].ssid, ssids[i].ssid_len);
		parm.ssid[i].SsidLength = ssids[i].ssid_len;
	}
	parm.ssid_num = i;

	/* no ssid entry, set the scan type as passvie */
	if (request->n_ssids == 0)
		parm.scan_mode = SCAN_PASSIVE;

	/* parsing channels, n_channels */
	for (i = 0; i < request->n_channels && i < RTW_CHANNEL_SCAN_AMOUNT; i++) {
		#ifdef CONFIG_DEBUG_CFG80211
		RTW_INFO(FUNC_ADPT_FMT CHAN_FMT"\n", FUNC_ADPT_ARG(padapter), CHAN_ARG(request->channels[i]));
		#endif
		parm.ch[i].hw_value = request->channels[i]->hw_value;
		parm.ch[i].flags = request->channels[i]->flags;
	}
	parm.ch_num = i;

	if (request->n_channels == 1) {
		for (i = 1; i < survey_times_for_one_ch; i++)
			_rtw_memcpy(&parm.ch[i], &parm.ch[0], sizeof(struct rtw_ieee80211_channel));
		parm.ch_num = survey_times_for_one_ch;
	} else if (request->n_channels <= 4) {
		for (j = request->n_channels - 1; j >= 0; j--)
			for (i = 0; i < survey_times; i++)
				_rtw_memcpy(&parm.ch[j * survey_times + i], &parm.ch[j], sizeof(struct rtw_ieee80211_channel));
		parm.ch_num = survey_times * request->n_channels;
	}

	_enter_critical_bh(&pwdev_priv->scan_req_lock, &irqL);
	_enter_critical_bh(&pmlmepriv->lock, &irqL);
	_status = rtw_sitesurvey_cmd(padapter, &parm);
	if (_status == _SUCCESS)
		pwdev_priv->scan_request = request;
	else
		ret = -1;
	_exit_critical_bh(&pmlmepriv->lock, &irqL);
	_exit_critical_bh(&pwdev_priv->scan_req_lock, &irqL);

check_need_indicate_scan_done:
	if (_TRUE == need_indicate_scan_done) {
#if (KERNEL_VERSION(4, 8, 0) <= LINUX_VERSION_CODE)
		struct cfg80211_scan_info info;

		memset(&info, 0, sizeof(info));
		info.aborted = 0;
#endif
		/* the process time of scan results must be over at least 1ms in the newly Android */
		rtw_msleep_os(1); 

		_rtw_cfg80211_surveydone_event_callback(padapter, request);
#if (KERNEL_VERSION(4, 8, 0) <= LINUX_VERSION_CODE)
		cfg80211_scan_done(request, &info);
#else
		cfg80211_scan_done(request, 0);
#endif
	}

	if (ps_denied == _TRUE)
		rtw_ps_deny_cancel(padapter, PS_DENY_SCAN);

exit:
#ifdef RTW_BUSY_DENY_SCAN
	if (pmlmepriv)
		pmlmepriv->lastscantime = rtw_get_current_time();
#endif

	return ret;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)) && \
    defined(CONFIG_RTW_ABORT_SCAN)
static void cfg80211_rtw_abort_scan(struct wiphy *wiphy,
				    struct wireless_dev *wdev)
{
	_adapter *padapter = wiphy_to_adapter(wiphy);

	RTW_INFO("=>"FUNC_ADPT_FMT" - Abort Scan\n", FUNC_ADPT_ARG(padapter));
	if (wdev->iftype != NL80211_IFTYPE_STATION) {
		RTW_ERR("abort scan ignored, iftype(%d)\n", wdev->iftype);
		return;
	}
	rtw_scan_abort(padapter);
}
#endif

static int cfg80211_rtw_set_wiphy_params(struct wiphy *wiphy,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0))
	int radio_idx,
#endif
	u32 changed)
{
#if 0
	struct iwm_priv *iwm = wiphy_to_iwm(wiphy);

	if (changed & WIPHY_PARAM_RTS_THRESHOLD &&
	    (iwm->conf.rts_threshold != wiphy->rts_threshold)) {
		int ret;

		iwm->conf.rts_threshold = wiphy->rts_threshold;

		ret = iwm_umac_set_config_fix(iwm, UMAC_PARAM_TBL_CFG_FIX,
				CFG_RTS_THRESHOLD,
				iwm->conf.rts_threshold);
		if (ret < 0)
			return ret;
	}

	if (changed & WIPHY_PARAM_FRAG_THRESHOLD &&
	    (iwm->conf.frag_threshold != wiphy->frag_threshold)) {
		int ret;

		iwm->conf.frag_threshold = wiphy->frag_threshold;

		ret = iwm_umac_set_config_fix(iwm, UMAC_PARAM_TBL_FA_CFG_FIX,
				CFG_FRAG_THRESHOLD,
				iwm->conf.frag_threshold);
		if (ret < 0)
			return ret;
	}
#endif
	RTW_INFO("%s\n", __func__);
	return 0;
}



static int rtw_cfg80211_set_wpa_version(struct security_priv *psecuritypriv, u32 wpa_version)
{
	RTW_INFO("%s, wpa_version=%d\n", __func__, wpa_version);

	if (!wpa_version) {
		psecuritypriv->ndisauthtype = Ndis802_11AuthModeOpen;
		return 0;
	}


	if (wpa_version & (NL80211_WPA_VERSION_1 | NL80211_WPA_VERSION_2))
		psecuritypriv->ndisauthtype = Ndis802_11AuthModeWPAPSK;

#if 0
	if (wpa_version & NL80211_WPA_VERSION_2)
		psecuritypriv->ndisauthtype = Ndis802_11AuthModeWPA2PSK;
#endif

	#ifdef CONFIG_WAPI_SUPPORT
	if (wpa_version & NL80211_WAPI_VERSION_1)
		psecuritypriv->ndisauthtype = Ndis802_11AuthModeWAPI;
	#endif

	return 0;

}

static int rtw_cfg80211_set_auth_type(struct security_priv *psecuritypriv,
		enum nl80211_auth_type sme_auth_type)
{
	RTW_INFO("%s, nl80211_auth_type=%d\n", __func__, sme_auth_type);

	if (NL80211_AUTHTYPE_MAX <= (int)MLME_AUTHTYPE_SAE) {
		if (MLME_AUTHTYPE_SAE == psecuritypriv->auth_type) {
			/* This case pre handle in
			 * rtw_check_connect_sae_compat()
			 */
			psecuritypriv->auth_alg = WLAN_AUTH_SAE;
			return 0;
		}
	} else if (sme_auth_type == (int)MLME_AUTHTYPE_SAE) {
		psecuritypriv->auth_type = MLME_AUTHTYPE_SAE;
		psecuritypriv->auth_alg = WLAN_AUTH_SAE;
		return 0;
	}

	psecuritypriv->auth_type = sme_auth_type;

	switch (sme_auth_type) {
	case NL80211_AUTHTYPE_AUTOMATIC:

		psecuritypriv->dot11AuthAlgrthm = dot11AuthAlgrthm_Auto;

		break;
	case NL80211_AUTHTYPE_OPEN_SYSTEM:

		psecuritypriv->dot11AuthAlgrthm = dot11AuthAlgrthm_Open;

		if (psecuritypriv->ndisauthtype > Ndis802_11AuthModeWPA)
			psecuritypriv->dot11AuthAlgrthm = dot11AuthAlgrthm_8021X;

#ifdef CONFIG_WAPI_SUPPORT
		if (psecuritypriv->ndisauthtype == Ndis802_11AuthModeWAPI)
			psecuritypriv->dot11AuthAlgrthm = dot11AuthAlgrthm_WAPI;
#endif

		break;
	case NL80211_AUTHTYPE_SHARED_KEY:

		psecuritypriv->dot11AuthAlgrthm = dot11AuthAlgrthm_Shared;

		psecuritypriv->ndisencryptstatus = Ndis802_11Encryption1Enabled;


		break;
	default:
		psecuritypriv->dot11AuthAlgrthm = dot11AuthAlgrthm_Open;
		/* return -ENOTSUPP; */
	}

	return 0;

}

static int rtw_cfg80211_set_cipher(struct security_priv *psecuritypriv, u32 cipher, bool ucast)
{
	u32 ndisencryptstatus = Ndis802_11EncryptionDisabled;

	u32 *profile_cipher = ucast ? &psecuritypriv->dot11PrivacyAlgrthm :
		&psecuritypriv->dot118021XGrpPrivacy;

	RTW_INFO("%s, ucast=%d, cipher=0x%x\n", __func__, ucast, cipher);


	if (!cipher) {
		*profile_cipher = _NO_PRIVACY_;
		psecuritypriv->ndisencryptstatus = ndisencryptstatus;
		return 0;
	}

	switch (cipher) {
	case IW_AUTH_CIPHER_NONE:
		*profile_cipher = _NO_PRIVACY_;
		ndisencryptstatus = Ndis802_11EncryptionDisabled;
#ifdef CONFIG_WAPI_SUPPORT
		if (psecuritypriv->dot11PrivacyAlgrthm == _SMS4_)
			*profile_cipher = _SMS4_;
#endif
		break;
	case WLAN_CIPHER_SUITE_WEP40:
		*profile_cipher = _WEP40_;
		ndisencryptstatus = Ndis802_11Encryption1Enabled;
		break;
	case WLAN_CIPHER_SUITE_WEP104:
		*profile_cipher = _WEP104_;
		ndisencryptstatus = Ndis802_11Encryption1Enabled;
		break;
	case WLAN_CIPHER_SUITE_TKIP:
		*profile_cipher = _TKIP_;
		ndisencryptstatus = Ndis802_11Encryption2Enabled;
		break;
	case WLAN_CIPHER_SUITE_CCMP:
		*profile_cipher = _AES_;
		ndisencryptstatus = Ndis802_11Encryption3Enabled;
		break;
	case WIFI_CIPHER_SUITE_GCMP:
		*profile_cipher = _GCMP_;
		ndisencryptstatus = Ndis802_11Encryption3Enabled;
		break;
	case WIFI_CIPHER_SUITE_GCMP_256:
		*profile_cipher = _GCMP_256_;
		ndisencryptstatus = Ndis802_11Encryption3Enabled;
		break;
	case WIFI_CIPHER_SUITE_CCMP_256:
		*profile_cipher = _CCMP_256_;
		ndisencryptstatus = Ndis802_11Encryption3Enabled;
		break;
#ifdef CONFIG_WAPI_SUPPORT
	case WLAN_CIPHER_SUITE_SMS4:
		*profile_cipher = _SMS4_;
		ndisencryptstatus = Ndis802_11_EncrypteionWAPI;
		break;
#endif
	default:
		RTW_INFO("Unsupported cipher: 0x%x\n", cipher);
		return -ENOTSUPP;
	}

	if (ucast) {
		psecuritypriv->ndisencryptstatus = ndisencryptstatus;

		/* if(psecuritypriv->dot11PrivacyAlgrthm >= _AES_) */
		/*	psecuritypriv->ndisauthtype = Ndis802_11AuthModeWPA2PSK; */
	}

	return 0;
}

static int rtw_cfg80211_set_key_mgt(struct security_priv *psecuritypriv, u32 key_mgt)
{
	RTW_INFO("%s, key_mgt=0x%x\n", __func__, key_mgt);

	if (key_mgt == WLAN_AKM_SUITE_8021X) {
		/* *auth_type = UMAC_AUTH_TYPE_8021X; */
		psecuritypriv->dot11AuthAlgrthm = dot11AuthAlgrthm_8021X;
		psecuritypriv->rsn_akm_suite_type = 1;
	} else if (key_mgt == WLAN_AKM_SUITE_PSK) {
		psecuritypriv->dot11AuthAlgrthm = dot11AuthAlgrthm_8021X;
		psecuritypriv->rsn_akm_suite_type = 2;
	}
#ifdef CONFIG_WAPI_SUPPORT
	else if (key_mgt == WLAN_AKM_SUITE_WAPI_PSK)
		psecuritypriv->dot11AuthAlgrthm = dot11AuthAlgrthm_WAPI;
	else if (key_mgt == WLAN_AKM_SUITE_WAPI_CERT)
		psecuritypriv->dot11AuthAlgrthm = dot11AuthAlgrthm_WAPI;
#endif
#ifdef CONFIG_RTW_80211R
	else if (key_mgt == WLAN_AKM_SUITE_FT_8021X) {
		psecuritypriv->dot11AuthAlgrthm = dot11AuthAlgrthm_8021X;
		psecuritypriv->rsn_akm_suite_type = 3;
	} else if (key_mgt == WLAN_AKM_SUITE_FT_PSK) {
		psecuritypriv->dot11AuthAlgrthm = dot11AuthAlgrthm_8021X;
		psecuritypriv->rsn_akm_suite_type = 4;
	}
#endif
	else if (key_mgt == WLAN_AKM_SUITE_SAE) { 
		psecuritypriv->rsn_akm_suite_type = 8; 
	} else {
		RTW_INFO("Invalid key mgt: 0x%x\n", key_mgt);
		/* return -EINVAL; */
	}

	return 0;
}

static int rtw_cfg80211_set_wpa_ie(_adapter *padapter, u8 *pie, size_t ielen)
{
	u8 *buf = NULL, *pos = NULL;
	int group_cipher = 0, pairwise_cipher = 0;
	u8 mfp_opt = MFP_NO;
	int ret = 0;
	int wpa_ielen = 0;
	int wpa2_ielen = 0;
	u8 *pwpa, *pwpa2;
	u8 null_addr[] = {0, 0, 0, 0, 0, 0};

	if (pie == NULL || !ielen) {
		/* Treat this as normal case, but need to clear WIFI_UNDER_WPS */
		_clr_fwstate_(&padapter->mlmepriv, WIFI_UNDER_WPS);
		goto exit;
	}

	if (ielen > MAX_WPA_IE_LEN + MAX_WPS_IE_LEN + MAX_P2P_IE_LEN) {
		ret = -EINVAL;
		goto exit;
	}

	buf = rtw_zmalloc(ielen);
	if (buf == NULL) {
		ret =  -ENOMEM;
		goto exit;
	}

	_rtw_memcpy(buf, pie , ielen);

	RTW_INFO("set wpa_ie(length:%zu):\n", ielen);
	RTW_INFO_DUMP(NULL, buf, ielen);

	pos = buf;
	if (ielen < RSN_HEADER_LEN) {
		ret  = -1;
		goto exit;
	}

	pwpa = rtw_get_wpa_ie(buf, &wpa_ielen, ielen);
	if (pwpa && wpa_ielen > 0) {
		if (rtw_parse_wpa_ie(pwpa, wpa_ielen + 2, &group_cipher, &pairwise_cipher, NULL) == _SUCCESS) {
			padapter->securitypriv.dot11AuthAlgrthm = dot11AuthAlgrthm_8021X;
			padapter->securitypriv.ndisauthtype = Ndis802_11AuthModeWPAPSK;
			_rtw_memcpy(padapter->securitypriv.supplicant_ie, &pwpa[0], wpa_ielen + 2);

			RTW_INFO("got wpa_ie, wpa_ielen:%u\n", wpa_ielen);
		}
	}

	pwpa2 = rtw_get_wpa2_ie(buf, &wpa2_ielen, ielen);
	if (pwpa2 && wpa2_ielen > 0) {
		if (rtw_parse_wpa2_ie(pwpa2, wpa2_ielen + 2, &group_cipher, &pairwise_cipher, NULL, NULL, &mfp_opt, NULL) == _SUCCESS) {
			padapter->securitypriv.dot11AuthAlgrthm = dot11AuthAlgrthm_8021X;
			padapter->securitypriv.ndisauthtype = Ndis802_11AuthModeWPA2PSK;
			_rtw_memcpy(padapter->securitypriv.supplicant_ie, &pwpa2[0], wpa2_ielen + 2);

			RTW_INFO("got wpa2_ie, wpa2_ielen:%u\n", wpa2_ielen);
		}
	}

	if (group_cipher == 0)
		group_cipher = WPA_CIPHER_NONE;
	if (pairwise_cipher == 0)
		pairwise_cipher = WPA_CIPHER_NONE;

	switch (group_cipher) {
	case WPA_CIPHER_NONE:
		padapter->securitypriv.dot118021XGrpPrivacy = _NO_PRIVACY_;
		padapter->securitypriv.ndisencryptstatus = Ndis802_11EncryptionDisabled;
		break;
	case WPA_CIPHER_WEP40:
		padapter->securitypriv.dot118021XGrpPrivacy = _WEP40_;
		padapter->securitypriv.ndisencryptstatus = Ndis802_11Encryption1Enabled;
		break;
	case WPA_CIPHER_TKIP:
		padapter->securitypriv.dot118021XGrpPrivacy = _TKIP_;
		padapter->securitypriv.ndisencryptstatus = Ndis802_11Encryption2Enabled;
		break;
	case WPA_CIPHER_CCMP:
		padapter->securitypriv.dot118021XGrpPrivacy = _AES_;
		padapter->securitypriv.ndisencryptstatus = Ndis802_11Encryption3Enabled;
		break;
	case WPA_CIPHER_GCMP:
		padapter->securitypriv.dot118021XGrpPrivacy = _GCMP_;
		padapter->securitypriv.ndisencryptstatus = Ndis802_11Encryption3Enabled;
		break;
	case WPA_CIPHER_GCMP_256:
		padapter->securitypriv.dot118021XGrpPrivacy = _GCMP_256_;
		padapter->securitypriv.ndisencryptstatus = Ndis802_11Encryption3Enabled;
		break;
	case WPA_CIPHER_CCMP_256:
		padapter->securitypriv.dot118021XGrpPrivacy = _CCMP_256_;
		padapter->securitypriv.ndisencryptstatus = Ndis802_11Encryption3Enabled;
		break;
	case WPA_CIPHER_WEP104:
		padapter->securitypriv.dot118021XGrpPrivacy = _WEP104_;
		padapter->securitypriv.ndisencryptstatus = Ndis802_11Encryption1Enabled;
		break;
	}

	switch (pairwise_cipher) {
	case WPA_CIPHER_NONE:
		padapter->securitypriv.dot11PrivacyAlgrthm = _NO_PRIVACY_;
		padapter->securitypriv.ndisencryptstatus = Ndis802_11EncryptionDisabled;
		break;
	case WPA_CIPHER_WEP40:
		padapter->securitypriv.dot11PrivacyAlgrthm = _WEP40_;
		padapter->securitypriv.ndisencryptstatus = Ndis802_11Encryption1Enabled;
		break;
	case WPA_CIPHER_TKIP:
		padapter->securitypriv.dot11PrivacyAlgrthm = _TKIP_;
		padapter->securitypriv.ndisencryptstatus = Ndis802_11Encryption2Enabled;
		break;
	case WPA_CIPHER_CCMP:
		padapter->securitypriv.dot11PrivacyAlgrthm = _AES_;
		padapter->securitypriv.ndisencryptstatus = Ndis802_11Encryption3Enabled;
		break;
	case WPA_CIPHER_GCMP:
		padapter->securitypriv.dot11PrivacyAlgrthm = _GCMP_;
		padapter->securitypriv.ndisencryptstatus = Ndis802_11Encryption3Enabled;
		break;
	case WPA_CIPHER_GCMP_256:
		padapter->securitypriv.dot11PrivacyAlgrthm = _GCMP_256_;
		padapter->securitypriv.ndisencryptstatus = Ndis802_11Encryption3Enabled;
		break;
	case WPA_CIPHER_CCMP_256:
		padapter->securitypriv.dot11PrivacyAlgrthm = _CCMP_256_;
		padapter->securitypriv.ndisencryptstatus = Ndis802_11Encryption3Enabled;
		break;
	case WPA_CIPHER_WEP104:
		padapter->securitypriv.dot11PrivacyAlgrthm = _WEP104_;
		padapter->securitypriv.ndisencryptstatus = Ndis802_11Encryption1Enabled;
		break;
	}

	if (mfp_opt == MFP_INVALID) {
		RTW_INFO(FUNC_ADPT_FMT" invalid MFP setting\n", FUNC_ADPT_ARG(padapter));
		ret = -EINVAL;
		goto exit;
	}
	padapter->securitypriv.mfp_opt = mfp_opt;

	{/* handle wps_ie */
		uint wps_ielen;
		u8 *wps_ie;

		wps_ie = rtw_get_wps_ie(buf, ielen, NULL, &wps_ielen);
		if (wps_ie && wps_ielen > 0) {
			RTW_INFO("got wps_ie, wps_ielen:%u\n", wps_ielen);
			padapter->securitypriv.wps_ie_len = wps_ielen < MAX_WPS_IE_LEN ? wps_ielen : MAX_WPS_IE_LEN;
			_rtw_memcpy(padapter->securitypriv.wps_ie, wps_ie, padapter->securitypriv.wps_ie_len);
			set_fwstate(&padapter->mlmepriv, WIFI_UNDER_WPS);
		} else
			_clr_fwstate_(&padapter->mlmepriv, WIFI_UNDER_WPS);
	}

	{/* handle owe_ie */
		uint owe_ielen;
		u8 *owe_ie;

		owe_ie = rtw_get_owe_ie(buf, ielen, NULL, &owe_ielen);
		if (owe_ie && owe_ielen > 0) {
			RTW_INFO("got owe_ie, owe_ielen:%u\n", owe_ielen);
			padapter->securitypriv.owe_ie_len = owe_ielen < MAX_OWE_IE_LEN ? owe_ielen : MAX_OWE_IE_LEN;
			_rtw_memcpy(padapter->securitypriv.owe_ie, owe_ie, padapter->securitypriv.owe_ie_len);
		}
	}

	#ifdef CONFIG_P2P
	{/* check p2p_ie for assoc req; */
		uint p2p_ielen = 0;
		u8 *p2p_ie;
		struct mlme_priv *pmlmepriv = &(padapter->mlmepriv);

		p2p_ie = rtw_get_p2p_ie(buf, ielen, NULL, &p2p_ielen);
		if (p2p_ie) {
			#ifdef CONFIG_DEBUG_CFG80211
			RTW_INFO("%s p2p_assoc_req_ielen=%d\n", __FUNCTION__, p2p_ielen);
			#endif

			if (pmlmepriv->p2p_assoc_req_ie) {
				u32 free_len = pmlmepriv->p2p_assoc_req_ie_len;
				pmlmepriv->p2p_assoc_req_ie_len = 0;
				rtw_mfree(pmlmepriv->p2p_assoc_req_ie, free_len);
				pmlmepriv->p2p_assoc_req_ie = NULL;
			}

			pmlmepriv->p2p_assoc_req_ie = rtw_malloc(p2p_ielen);
			if (pmlmepriv->p2p_assoc_req_ie == NULL) {
				RTW_INFO("%s()-%d: rtw_malloc() ERROR!\n", __FUNCTION__, __LINE__);
				goto exit;
			}
			_rtw_memcpy(pmlmepriv->p2p_assoc_req_ie, p2p_ie, p2p_ielen);
			pmlmepriv->p2p_assoc_req_ie_len = p2p_ielen;
		}
	}
	#endif /* CONFIG_P2P */

	#ifdef CONFIG_WFD
	{
		uint wfd_ielen = 0;
		u8 *wfd_ie;
		struct mlme_priv *pmlmepriv = &(padapter->mlmepriv);

		wfd_ie = rtw_get_wfd_ie(buf, ielen, NULL, &wfd_ielen);
		if (wfd_ie) {
			#ifdef CONFIG_DEBUG_CFG80211
			RTW_INFO("%s wfd_assoc_req_ielen=%d\n", __FUNCTION__, wfd_ielen);
			#endif

			if (rtw_mlme_update_wfd_ie_data(pmlmepriv, MLME_ASSOC_REQ_IE, wfd_ie, wfd_ielen) != _SUCCESS)
				goto exit;
		}
	}
	#endif /* CONFIG_WFD */

	#ifdef CONFIG_RTW_MULTI_AP
	padapter->multi_ap = rtw_get_multi_ap_ie_ext(buf, ielen) & MULTI_AP_BACKHAUL_STA;
	if (padapter->multi_ap)
		adapter_set_use_wds(padapter, 1);
	#endif

	/* TKIP and AES disallow multicast packets until installing group key */
	if (padapter->securitypriv.dot11PrivacyAlgrthm == _TKIP_
		|| padapter->securitypriv.dot11PrivacyAlgrthm == _TKIP_WTMIC_
		|| padapter->securitypriv.dot11PrivacyAlgrthm == _AES_
		|| padapter->securitypriv.dot11PrivacyAlgrthm == _GCMP_
		|| padapter->securitypriv.dot11PrivacyAlgrthm == _GCMP_256_
		|| padapter->securitypriv.dot11PrivacyAlgrthm == _CCMP_256_)
		/* WPS open need to enable multicast */
		/* || check_fwstate(&padapter->mlmepriv, WIFI_UNDER_WPS) == _TRUE) */
		rtw_hal_set_hwreg(padapter, HW_VAR_OFF_RCR_AM, null_addr);


exit:
	if (buf)
		rtw_mfree(buf, ielen);
	if (ret)
		_clr_fwstate_(&padapter->mlmepriv, WIFI_UNDER_WPS);

	return ret;
}

static int cfg80211_rtw_join_ibss(struct wiphy *wiphy, struct net_device *ndev,
				  struct cfg80211_ibss_params *params)
{
	_adapter *padapter = (_adapter *)rtw_netdev_priv(ndev);
	NDIS_802_11_SSID ndis_ssid;
	struct security_priv *psecuritypriv = &padapter->securitypriv;
	struct mlme_ext_priv *pmlmeext = &padapter->mlmeextpriv;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0))
	struct cfg80211_chan_def *pch_def;
#endif
	struct ieee80211_channel *pch;
	int ret = 0;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0))
	pch_def = (struct cfg80211_chan_def *)(&params->chandef);
	pch = (struct ieee80211_channel *) pch_def->chan;
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31))
	pch = (struct ieee80211_channel *)(params->channel);
#endif

	if (!params->ssid || !params->ssid_len) {
		ret = -EINVAL;
		goto exit;
	}

	if (params->ssid_len > IW_ESSID_MAX_SIZE) {
		ret = -E2BIG;
		goto exit;
	}

	rtw_ps_deny(padapter, PS_DENY_JOIN);
	if (_FAIL == rtw_pwr_wakeup(padapter)) {
		ret = -EPERM;
		goto cancel_ps_deny;
	}

#ifdef CONFIG_CONCURRENT_MODE
	if (rtw_mi_buddy_check_fwstate(padapter, WIFI_UNDER_LINKING)) {
		RTW_INFO("%s, but buddy_intf is under linking\n", __FUNCTION__);
		ret = -EINVAL;
		goto cancel_ps_deny;
	}
	rtw_mi_buddy_scan_abort(padapter, _TRUE); /* OR rtw_mi_scan_abort(padapter, _TRUE);*/
#endif /*CONFIG_CONCURRENT_MODE*/


	_rtw_memset(&ndis_ssid, 0, sizeof(NDIS_802_11_SSID));
	ndis_ssid.SsidLength = params->ssid_len;
	_rtw_memcpy(ndis_ssid.Ssid, (u8 *)params->ssid, params->ssid_len);

	/* RTW_INFO("ssid=%s, len=%zu\n", ndis_ssid.Ssid, params->ssid_len); */

	psecuritypriv->ndisencryptstatus = Ndis802_11EncryptionDisabled;
	psecuritypriv->dot11PrivacyAlgrthm = _NO_PRIVACY_;
	psecuritypriv->dot118021XGrpPrivacy = _NO_PRIVACY_;
	psecuritypriv->dot11AuthAlgrthm = dot11AuthAlgrthm_Open; /* open system */
	psecuritypriv->ndisauthtype = Ndis802_11AuthModeOpen;

	ret = rtw_cfg80211_set_auth_type(psecuritypriv, NL80211_AUTHTYPE_OPEN_SYSTEM);
	rtw_set_802_11_authentication_mode(padapter, psecuritypriv->ndisauthtype);

	RTW_INFO("%s: center_freq = %d\n", __func__, pch->center_freq);
	pmlmeext->cur_channel = rtw_freq2ch(pch->center_freq);

	if (rtw_set_802_11_ssid(padapter, &ndis_ssid) == _FALSE) {
		ret = -1;
		goto cancel_ps_deny;
	}

cancel_ps_deny:
	rtw_ps_deny_cancel(padapter, PS_DENY_JOIN);
exit:
	return ret;
}

static int cfg80211_rtw_leave_ibss(struct wiphy *wiphy, struct net_device *ndev)
{
	_adapter *padapter = (_adapter *)rtw_netdev_priv(ndev);
	struct wireless_dev *rtw_wdev = padapter->rtw_wdev;
	enum nl80211_iftype old_type;
	int ret = 0;

	RTW_INFO(FUNC_NDEV_FMT"\n", FUNC_NDEV_ARG(ndev));

#if (RTW_CFG80211_BLOCK_STA_DISCON_EVENT & RTW_CFG80211_BLOCK_DISCON_WHEN_DISCONNECT)
	rtw_wdev_set_not_indic_disco(adapter_wdev_data(padapter), 1);
#endif

	old_type = rtw_wdev->iftype;

	rtw_set_to_roam(padapter, 0);

	if (check_fwstate(&padapter->mlmepriv, WIFI_ASOC_STATE)) {
		rtw_scan_abort(padapter);
		LeaveAllPowerSaveMode(padapter);

		rtw_wdev->iftype = NL80211_IFTYPE_STATION;

		if (rtw_set_802_11_infrastructure_mode(padapter, Ndis802_11Infrastructure, 0) == _FALSE) {
			rtw_wdev->iftype = old_type;
			ret = -EPERM;
			goto leave_ibss;
		}
		rtw_setopmode_cmd(padapter, Ndis802_11Infrastructure, RTW_CMDF_WAIT_ACK);
	}

leave_ibss:
#if (RTW_CFG80211_BLOCK_STA_DISCON_EVENT & RTW_CFG80211_BLOCK_DISCON_WHEN_DISCONNECT)
	rtw_wdev_set_not_indic_disco(adapter_wdev_data(padapter), 0);
#endif

	return 0;
}

bool rtw_cfg80211_is_connect_requested(_adapter *adapter)
{
	struct rtw_wdev_priv *pwdev_priv = adapter_wdev_data(adapter);
	_irqL irqL;
	bool requested;

	_enter_critical_bh(&pwdev_priv->connect_req_lock, &irqL);
	requested = pwdev_priv->connect_req ? 1 : 0;
	_exit_critical_bh(&pwdev_priv->connect_req_lock, &irqL);

	return requested;
}

static int _rtw_disconnect(struct wiphy *wiphy, struct net_device *ndev)
{
	_adapter *padapter = (_adapter *)rtw_netdev_priv(ndev);


	/* if(check_fwstate(&padapter->mlmepriv, WIFI_ASOC_STATE)) */
	{
		rtw_scan_abort(padapter);
		rtw_join_abort_timeout(padapter, 300);
		LeaveAllPowerSaveMode(padapter);
		rtw_disassoc_cmd(padapter, 500, RTW_CMDF_WAIT_ACK);
#ifdef CONFIG_RTW_REPEATER_SON
		rtw_rson_do_disconnect(padapter);
#endif
		RTW_INFO("%s...call rtw_indicate_disconnect\n", __func__);

		rtw_free_assoc_resources_cmd(padapter, _TRUE, RTW_CMDF_WAIT_ACK);

		/* indicate locally_generated = 0 when suspend */
		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0))
		rtw_indicate_disconnect(padapter, 0, wiphy->dev.power.is_prepared ? _FALSE : _TRUE);
		#else
		/*
		* for kernel < 4.2, DISCONNECT event is hardcoded with
		* NL80211_ATTR_DISCONNECTED_BY_AP=1 in NL80211 layer
		* no need to judge if under suspend
		*/
		rtw_indicate_disconnect(padapter, 0, _TRUE);
		#endif

		rtw_pwr_wakeup(padapter);
	}
	return 0;
}

#if (KERNEL_VERSION(4, 17, 0) > LINUX_VERSION_CODE) \
    && !defined(CONFIG_KERNEL_PATCH_EXTERNAL_AUTH)
static bool rtw_check_connect_sae_compat(struct cfg80211_connect_params *sme)
{
	struct rtw_ieee802_11_elems elems;
	struct rsne_info info;
	u8 AKM_SUITE_SAE[] = { 0x00, 0x0f, 0xac, 8 };
	int i;

	if (sme->auth_type != (int)MLME_AUTHTYPE_SHARED_KEY)
		return false;

	if (rtw_ieee802_11_parse_elems((u8 *)sme->ie, sme->ie_len, &elems, 0)
	    == ParseFailed)
		return false;

	if (!elems.rsn_ie)
		return false;

	if (rtw_rsne_info_parse(elems.rsn_ie - 2, elems.rsn_ie_len + 2, &info) == _FAIL)
		return false;

	for (i = 0; i < info.akm_cnt; i++)
		if (memcmp(info.akm_list + i * RSN_SELECTOR_LEN,
			   AKM_SUITE_SAE, RSN_SELECTOR_LEN) == 0)
			return true;

	return false;
}
#else
#define rtw_check_connect_sae_compat(sme)	false
#endif

static int cfg80211_rtw_connect(struct wiphy *wiphy, struct net_device *ndev,
				struct cfg80211_connect_params *sme)
{
	int ret = 0;
	NDIS_802_11_AUTHENTICATION_MODE authmode;
	NDIS_802_11_SSID ndis_ssid;
	/* u8 matched_by_bssid=_FALSE; */
	/* u8 matched_by_ssid=_FALSE; */
	_adapter *padapter = (_adapter *)rtw_netdev_priv(ndev);
	struct security_priv *psecuritypriv = &padapter->securitypriv;
	struct rtw_wdev_priv *pwdev_priv = adapter_wdev_data(padapter);
	struct mlme_priv *pmlmepriv = &(padapter->mlmepriv);
	_irqL irqL;

#if (RTW_CFG80211_BLOCK_STA_DISCON_EVENT & RTW_CFG80211_BLOCK_DISCON_WHEN_CONNECT)
	rtw_wdev_set_not_indic_disco(pwdev_priv, 1);
#endif

	RTW_INFO("=>"FUNC_NDEV_FMT" - Start to Connection\n", FUNC_NDEV_ARG(ndev));
	RTW_INFO("privacy=%d, key=%p, key_len=%d, key_idx=%d, auth_type=%d\n",
		sme->privacy, sme->key, sme->key_len, sme->key_idx, sme->auth_type);

	if (rtw_check_connect_sae_compat(sme)) {
		sme->auth_type = (int)MLME_AUTHTYPE_SAE;
		psecuritypriv->auth_type = MLME_AUTHTYPE_SAE;
		psecuritypriv->auth_alg = WLAN_AUTH_SAE;
		RTW_INFO("%s set sme->auth_type for SAE compat\n", __FUNCTION__);
	}

	if (pwdev_priv->block == _TRUE) {
		ret = -EBUSY;
		RTW_INFO("%s wdev_priv.block is set\n", __FUNCTION__);
		goto exit;
	}

       if (check_fwstate(pmlmepriv, WIFI_ASOC_STATE | WIFI_UNDER_LINKING) == _TRUE) {

		_rtw_disconnect(wiphy, ndev);
		RTW_INFO("%s disconnect before connecting! fw_state=0x%x\n",
			__FUNCTION__, pmlmepriv->fw_state);
	}

#ifdef CONFIG_PLATFORM_MSTAR_SCAN_BEFORE_CONNECT
	printk("MStar Android!\n");
	if (pwdev_priv->bandroid_scan == _FALSE) {
#ifdef CONFIG_P2P
		struct wifidirect_info *pwdinfo = &(padapter->wdinfo);
		if (rtw_p2p_chk_state(pwdinfo, P2P_STATE_NONE))
#endif /* CONFIG_P2P */
		{
			ret = -EBUSY;
			printk("Android hasn't attached yet!\n");
			goto exit;
		}
	}
#endif

	if (!sme->ssid || !sme->ssid_len) {
		ret = -EINVAL;
		goto exit;
	}

	if (sme->ssid_len > IW_ESSID_MAX_SIZE) {
		ret = -E2BIG;
		goto exit;
	}

	rtw_ps_deny(padapter, PS_DENY_JOIN);
	if (_FAIL == rtw_pwr_wakeup(padapter)) {
		ret = -EPERM;
		goto cancel_ps_deny;
	}

	rtw_mi_scan_abort(padapter, _TRUE);

	rtw_join_abort_timeout(padapter, 300);
#ifdef CONFIG_CONCURRENT_MODE
	if (rtw_mi_buddy_check_fwstate(padapter, WIFI_UNDER_LINKING)) {
		ret = -EINVAL;
		goto cancel_ps_deny;
	}
#endif

	_rtw_memset(&ndis_ssid, 0, sizeof(NDIS_802_11_SSID));
	ndis_ssid.SsidLength = sme->ssid_len;
	_rtw_memcpy(ndis_ssid.Ssid, (u8 *)sme->ssid, sme->ssid_len);

	RTW_INFO("ssid=%s, len=%zu\n", ndis_ssid.Ssid, sme->ssid_len);


	if (sme->bssid)
		RTW_INFO("bssid="MAC_FMT"\n", MAC_ARG(sme->bssid));


	psecuritypriv->ndisencryptstatus = Ndis802_11EncryptionDisabled;
	psecuritypriv->dot11PrivacyAlgrthm = _NO_PRIVACY_;
	psecuritypriv->dot118021XGrpPrivacy = _NO_PRIVACY_;
	psecuritypriv->dot11AuthAlgrthm = dot11AuthAlgrthm_Open; /* open system */
	psecuritypriv->ndisauthtype = Ndis802_11AuthModeOpen;
	psecuritypriv->auth_alg = WLAN_AUTH_OPEN;
	psecuritypriv->extauth_status = WLAN_STATUS_UNSPECIFIED_FAILURE;

#ifdef CONFIG_WAPI_SUPPORT
	padapter->wapiInfo.bWapiEnable = false;
#endif

	ret = rtw_cfg80211_set_wpa_version(psecuritypriv, sme->crypto.wpa_versions);
	if (ret < 0)
		goto cancel_ps_deny;

#ifdef CONFIG_WAPI_SUPPORT
	if (sme->crypto.wpa_versions & NL80211_WAPI_VERSION_1) {
		padapter->wapiInfo.bWapiEnable = true;
		padapter->wapiInfo.extra_prefix_len = WAPI_EXT_LEN;
		padapter->wapiInfo.extra_postfix_len = SMS4_MIC_LEN;
	}
#endif

	ret = rtw_cfg80211_set_auth_type(psecuritypriv, sme->auth_type);

#ifdef CONFIG_WAPI_SUPPORT
	if (psecuritypriv->dot11AuthAlgrthm == dot11AuthAlgrthm_WAPI)
		padapter->mlmeextpriv.mlmext_info.auth_algo = psecuritypriv->dot11AuthAlgrthm;
#endif


	if (ret < 0)
		goto cancel_ps_deny;

	RTW_INFO("%s, ie_len=%zu\n", __func__, sme->ie_len);

	ret = rtw_cfg80211_set_wpa_ie(padapter, (u8 *)sme->ie, sme->ie_len);
	if (ret < 0)
		goto cancel_ps_deny;

	if (sme->crypto.n_ciphers_pairwise) {
		ret = rtw_cfg80211_set_cipher(psecuritypriv, sme->crypto.ciphers_pairwise[0], _TRUE);
		if (ret < 0)
			goto cancel_ps_deny;
	}

	/* For WEP Shared auth */
	if (sme->key_len > 0 && sme->key) {
		u32 wep_key_idx, wep_key_len, wep_total_len;
		NDIS_802_11_WEP	*pwep = NULL;
		RTW_INFO("%s(): Shared/Auto WEP\n", __FUNCTION__);

		wep_key_idx = sme->key_idx;
		wep_key_len = sme->key_len;

		if (sme->key_idx > WEP_KEYS) {
			ret = -EINVAL;
			goto cancel_ps_deny;
		}

		if (wep_key_len > 0) {
			wep_key_len = wep_key_len <= 5 ? 5 : 13;
			wep_total_len = wep_key_len + FIELD_OFFSET(NDIS_802_11_WEP, KeyMaterial);
			pwep = (NDIS_802_11_WEP *) rtw_malloc(wep_total_len);
			if (pwep == NULL) {
				RTW_INFO(" wpa_set_encryption: pwep allocate fail !!!\n");
				ret = -ENOMEM;
				goto cancel_ps_deny;
			}

			_rtw_memset(pwep, 0, wep_total_len);

			pwep->KeyLength = wep_key_len;
			pwep->Length = wep_total_len;

			if (wep_key_len == 13) {
				padapter->securitypriv.dot11PrivacyAlgrthm = _WEP104_;
				padapter->securitypriv.dot118021XGrpPrivacy = _WEP104_;
			}
		} else {
			ret = -EINVAL;
			goto cancel_ps_deny;
		}

		pwep->KeyIndex = wep_key_idx;
		pwep->KeyIndex |= 0x80000000;

		_rtw_memcpy(pwep->KeyMaterial, (void *)sme->key, pwep->KeyLength);

		if (rtw_set_802_11_add_wep(padapter, pwep) == (u8)_FAIL)
			ret = -EOPNOTSUPP ;

		if (pwep)
			rtw_mfree((u8 *)pwep, wep_total_len);

		if (ret < 0)
			goto cancel_ps_deny;
	}

	ret = rtwI encountered an error doing what you asked. Could you try again?
