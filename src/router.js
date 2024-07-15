
class ChannelRouter {

	constructor() {
		this.channelConfig = [
			{ key: new RegExp(".*"), channel: null },
		];
	}

	addRoute(pattern, channel) {
		this.channelConfig = _.concat(this.channelConfig, { key: new RegExp(pattern), channel: channel });
	}

	resolveChannel(eventDef) {
		const accountId = eventDef.getAccountId();
		const service = eventDef.getSource();
		const detailType = eventDef.getDetailType();

		const eventKey = `${accountId}-${service}-${detailType}`;
		console.log("Looking up channel override for event " +eventKey);

		let matches = [];

		for (const channel of this.channelConfig) {
			const key = channel.key;

			if (key.test(eventKey)) {
				matches = _.concat(matches, [channel.channel]);
			}
		}

		const result = _.uniq(matches);

		if (result.length === 0) {
			return [null];
		}

		return result;
	}
}


module.exports = ChannelRouter;
