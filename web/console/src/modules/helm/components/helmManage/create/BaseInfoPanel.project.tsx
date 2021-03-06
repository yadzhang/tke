import * as React from 'react';
import { RootProps } from '../../HelmApp';
import classNames from 'classnames';
import { CommonBar, FormItem, FormPanel } from '../../../../common/components';
import { FetchState } from '@tencent/qcloud-redux-fetcher';
import { helmResourceList, TencentHubType } from '../../../constants/Config';
import { t, Trans } from '@tencent/tea-app/lib/i18n';
export class BaseInfoPanel extends React.Component<RootProps, {}> {
  componentDidMount() {
    const { actions } = this.props;
    actions.create.fetchRegionList();
    // actions.create.getToken();
    // actions.create.selectTencenthubType(TencentHubType.Public);
  }
  onChangeName(name: string) {
    let {
      actions,
      helmCreation: { isValid }
    } = this.props;
    actions.create.inputName(name);
  }
  onSelectResource(resource: string) {
    this.props.actions.create.selectResource(resource);
  }

  render() {
    let {
      namespaceSelection,
      namespaceList,
      actions,
      listState: { cluster },
      helmCreation: { name, resourceSelection, isValid }
    } = this.props;
    let namespaceOptions = namespaceList.data.records.map((p, index) => ({
      text: p.name,
      value: p.name
    }));

    return (
      <div>
        <ul className="form-list">
          <FormItem label={t('应用名')}>
            <div
              className={classNames('form-unit', {
                'is-error': isValid.name !== ''
              })}
            >
              <input
                type="text"
                className="tc-15-input-text m"
                placeholder={t('请输入应用名称')}
                value={name}
                onChange={e => this.onChangeName((e.target.value + '').trim())}
              />
              <p className="form-input-help">
                {t('最长63个字符，只能包含小写字母、数字及分隔符("-")，且必须以小写字母开头，数字或小写字母结尾')}
              </p>
            </div>
          </FormItem>

          <FormItem label={t('运行集群')}>{cluster.selection ? cluster.selection.metadata.name : '-'}</FormItem>

          <FormItem label={t('命名空间')}>
            <div
              className={classNames('form-unit', {
                'is-error': namespaceSelection === ''
              })}
            >
              <FormPanel.Select
                label={'namespace'}
                options={namespaceOptions}
                value={namespaceSelection}
                onChange={value => actions.namespace.selectNamespace(value)}
              />
            </div>
          </FormItem>
        </ul>
        <hr className="hr-mod" />
        <ul className="form-list" style={{ marginBottom: 16 }}>
          <FormItem label={t('来源')}>
            <div className="form-unit">
              <CommonBar
                list={helmResourceList}
                value={resourceSelection}
                onSelect={item => {
                  this.onSelectResource(item.value + '');
                }}
                isNeedPureText={false}
              />

              {/* {resource === HelmResource.Helm &&
              this.renderHelmPanel()}
            {resource === HelmResource.Other &&
              this.renderOtherPanel()} */}
            </div>
          </FormItem>
        </ul>
      </div>
    );
  }
}
