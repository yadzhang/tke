import * as React from 'react';
import { RootProps } from '../../HelmApp';
import { RegionBar, DownMenu, DownMenuItem } from '../../../../common/components';
import { bindActionCreators } from '@tencent/qcloud-lib';
import { allActions } from '../../../actions';
import { connect } from 'react-redux';

import { router } from '../../../router';
import { t, Trans } from '@tencent/tea-app/lib/i18n';
import { Justify, Text, Icon, Select } from '@tencent/tea-component';
import { FetchState } from '@tencent/qcloud-redux-fetcher';

const routerSea = seajs.require('router');

const mapDispatchToProps = dispatch =>
  Object.assign({}, bindActionCreators({ actions: allActions }, dispatch), {
    dispatch
  });

@connect(
  state => state,
  mapDispatchToProps
)
export class HelmHeadPanel extends React.Component<RootProps, {}> {
  componentDidMount() {
    const {
        route,
        actions,
        listState: { region, cluster }
      } = this.props,
      urlParams = router.resolve(route);
    // 这里对从resouce列表返回后，判断当前的状态
    let isNeedFetchRegion = region.list.data.recordCount ? false : true;
    isNeedFetchRegion && actions.region.applyFilter({});
    actions.cluster.applyFilter({});

    if (region.selection && cluster.selection && (!route.queries['rid'] || !route.queries['clusterId'])) {
      router.navigate(
        urlParams,
        Object.assign({}, route.queries, { rid: region.selection.value, clusterId: cluster.selection.metadata.name })
      );
    }
  }
  onSelect(clusterId: string) {
    let {
      actions,
      listState: { cluster }
    } = this.props;

    let item = cluster.list.data.records.find(item => item.clusterId === clusterId);
    if (item) {
      actions.cluster.select(item);
    }
  }
  render() {
    let {
      actions,
      listState: { cluster }
    } = this.props;
    let clusterContent: React.ReactNode;

    if (cluster.list.fetched !== true || cluster.list.fetchState === FetchState.Fetching) {
      clusterContent = <Icon type="loading" />;
    } else {
      let clusterOptions = cluster.list.data.records.map(item => ({
        value: item.metadata.name,
        text: `${item.metadata.name}(${item.spec.displayName ? item.spec.displayName : '未命名'})`
      }));

      clusterContent = (
        <Select
          size="m"
          options={clusterOptions}
          value={cluster.selection ? cluster.selection.metadata.name : null}
          onChange={value => {
            let finder = cluster.list.data.records.find(item => item.metadata.name === value);
            actions.cluster.selectCluster(finder);
          }}
          placeholder={cluster.list.data.recordCount ? t('请选择集群') : t('当前地域暂无集群')}
        />
      );
    }

    return (
      <Justify
        left={
          <React.Fragment>
            <h2>{t('Helm应用')}</h2>
            <Text theme="label" className="text tea-mr-2n tea-ml-1n" verticalAlign="middle">
              {t('集群')}
            </Text>
            {clusterContent}
          </React.Fragment>
        }
      />
    );
  }
}
